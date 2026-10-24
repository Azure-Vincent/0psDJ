// Primers for the Windows, identity and container lessons.

import type { Primer } from '../types';

export const WINDOWS_RDP_PRIMER: Primer = {
  oneLiner: '**Remote Desktop** (RDP) lets you use a Windows server\'s desktop over the network on TCP port 3389. It works only if the feature is on, its service runs, the firewall allows it, and the user has the right to log on remotely.',
  analogy: `
A meeting room with a front desk. The room must be open (Remote Desktop enabled), someone must be at the desk (the TermService service), the building's door must let you in (Windows Defender Firewall, which has different rules depending on whether the building thinks it is at home, at work or in public: the **network profile**), and your name must be on the guest list (the "Remote Desktop Users" group).

Every check happens in order. Which one fails decides the error message you get.`,
  ideas: [
    {
      title: 'PowerShell works with objects',
      explain: 'Cmdlets like `Get-Service` return objects with properties, not text. You filter and choose properties with the pipeline (`Where-Object`, `Select-Object`, `Format-Table`).',
      example: 'On win01:\n```\nPS> Get-Service TermService | Select-Object Name, Status, StartType\n\nName        Status  StartType\n----        ------  ---------\nTermService Running Manual\n```',
    },
    {
      title: 'Firewall rules depend on the network profile',
      explain: 'Windows classifies each connection as **Domain**, **Private** or **Public**. Rules apply to some profiles only. On Public, the Remote Desktop rules are usually off.',
      example: '`Get-NetConnectionProfile` shows `NetworkCategory : Private` for Ethernet0. If it changes to Public after a network change, RDP is blocked even though the rule "Remote Desktop - User Mode (TCP-In)" is enabled for Private.',
    },
    {
      title: 'The connection has stages, each with its own error',
      explain: 'TCP to 3389 → TLS → Network Level Authentication (the password is checked) → the logon right. FreeRDP\'s error code tells you the stage.',
      example: 'ERRCONNECT_CONNECT_TRANSPORT_FAILED = TCP never connected (firewall). ERRCONNECT_LOGON_FAILURE = wrong password. ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES = authenticated, but not allowed to log on remotely.',
    },
    {
      title: 'Event logs are the server\'s diary',
      explain: 'Logons are in the **Security** log (4624 success, 4625 failure with a status code), service problems in the **System** log, RDP details in TerminalServices logs.',
      example: '`Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625} -MaxEvents 1 | Format-List Message` shows why the last logon failed and from which address.',
    },
  ],
  walkthrough: {
    title: 'alice connects from ws01 with "xfreerdp /v:win01.corp.lab /u:alice"',
    steps: [
      { label: 'TCP 3389', detail: 'ws01 opens a connection to 10.0.20.30:3389. The firewall on win01 must allow it for the current profile.' },
      { label: 'TLS', detail: 'win01 presents its self-signed RDP certificate; xfreerdp asks you to accept it the first time.' },
      { label: 'Network Level Authentication', detail: 'The password is checked before a session is created. A wrong password ends here, and win01 logs 4625.' },
      { label: 'Logon right', detail: 'win01 checks that alice is allowed to "log on through Remote Desktop Services": member of Administrators or Remote Desktop Users.' },
      { label: 'Session', detail: 'A desktop session starts and win01 logs 4624 with Logon Type 10 (RemoteInteractive). `qwinsta` lists it.' },
    ],
  },
  misconceptions: [
    { myth: 'If ping to the server works, RDP must be reachable.', truth: 'ICMP and TCP 3389 are separate firewall rules, and the profile matters. Test with `Test-NetConnection win01 -Port 3389` or `nc -zv win01 3389`.' },
    { myth: 'Adding the user to Administrators is the fix for "not authorized for remote login".', truth: 'It works, but gives full control of the server. Add them to Remote Desktop Users instead.' },
    { myth: 'PowerShell output is just text to grep.', truth: 'It is objects. Select properties (`Select-Object`) instead of parsing the formatted table.' },
  ],
  checks: [
    { q: 'Which TCP port does RDP use by default?', a: '3389' },
    { q: 'Which local group grants the right to log on with RDP without making someone an administrator?', a: 'Remote Desktop Users' },
    { q: 'Which Security event ID records a failed logon?', a: '4625' },
    { q: 'RDP stopped working after the server\'s network changed, though the rules are enabled. What do you check?', a: 'The network profile (`Get-NetConnectionProfile`): the rules may not apply to the new profile (e.g. Public).' },
  ],
};

export const AD_KERBEROS_PRIMER: Primer = {
  oneLiner: '**Active Directory** is the central list of users, groups and computers of a Windows domain. Members find the **domain controller** through DNS, trust it through a machine password (the secure channel), and send every domain logon to it for checking.',
  analogy: `
A company with a central HR office (the domain controller). Every branch office (member server) has a phone line to HR and a code word only it and HR know (the **secure channel**). When an employee shows up at a branch with their company badge, the branch calls HR to check it.

To call HR, the branch looks up HR's number in the company phone book (**DNS**, the SRV records). Wrong phone book, wrong code word or HR unreachable: no employee can log in at that branch, while local guest accounts still work.`,
  ideas: [
    {
      title: 'Members find the DC through DNS',
      explain: 'A member asks **its own DNS servers** for the SRV record `_ldap._tcp.dc._msdcs.<domain>`. Only DNS servers that host the AD zone can answer, so members must use the domain\'s DNS servers.',
      example: 'win01 with DNS server dc01 (10.0.20.5): `Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.ad.corp.lab` → dc01.ad.corp.lab port 389. With ns1 (10.0.10.53) instead: "DNS name does not exist", and domain logons fail.',
    },
    {
      title: 'Joining creates a computer account and a secure channel',
      explain: '`Add-Computer` creates WIN01$ in AD with a password only win01 and the DC know. win01 changes it automatically every 30 days. If the two copies differ, the trust is broken.',
      example: 'Reverting win01 to an old snapshot restores an old machine password: `Test-ComputerSecureChannel` → False. `Test-ComputerSecureChannel -Repair -Credential CORP\\Administrator` fixes it.',
    },
    {
      title: 'Access is granted to groups',
      explain: 'Users go into groups in AD (RDP-Users); servers grant rights to those groups (win01\'s local Remote Desktop Users contains CORP\\RDP-Users). Removing someone from the AD group removes their access everywhere.',
      example: '`Get-ADGroupMember RDP-Users` on dc01 lists alice. `Get-LocalGroupMember "Remote Desktop Users"` on win01 lists CORP\\RDP-Users.',
    },
    {
      title: 'Lockout protects passwords',
      explain: 'After 5 wrong passwords the account is locked. A device with an old saved password can lock an account again and again. The DC records which computer sent the bad passwords (event 4740).',
      example: 'alice changed her password; her old laptop keeps retrying with the old one. `Search-ADAccount -LockedOut` lists her; `Unlock-ADAccount alice` unlocks her, and the old laptop must be updated.',
    },
  ],
  walkthrough: {
    title: 'CORP\\alice logs on to win01 with Remote Desktop',
    steps: [
      { label: 'Find a DC', detail: 'win01 asks dc01 (its DNS server) for _ldap._tcp.dc._msdcs.ad.corp.lab and gets dc01.ad.corp.lab.' },
      { label: 'Use the secure channel', detail: 'Netlogon on win01 already has an authenticated channel to dc01, using WIN01$\'s machine password.' },
      { label: 'Check the password', detail: 'win01 passes alice\'s logon attempt to dc01 (NTLM pass-through). dc01 checks the password and the account state (enabled, not locked).' },
      { label: 'Collect groups and check the right', detail: 'dc01 returns alice\'s groups (RDP-Users). win01 sees that RDP-Users is in its local Remote Desktop Users group: the logon right is granted.' },
      { label: 'Session', detail: 'Security event 4624 on win01 with CORP\\alice. Every failure along the way has its own status code in 4625.' },
    ],
  },
  misconceptions: [
    { myth: 'Members can use any DNS server as long as it resolves Internet names.', truth: 'They must use AD-integrated DNS (the DCs), which forward everything else. Otherwise they cannot find the domain.' },
    { myth: 'Rejoining the domain is the fix for every trust error.', truth: 'Repairing the secure channel is enough and keeps the computer account and its group memberships.' },
    { myth: 'Resetting a locked user\'s password fixes the lockout.', truth: 'Unlock the account; the user knows their password. Find and fix the device sending the old password.' },
  ],
  checks: [
    { q: 'Which DNS record does a member query to find a domain controller?', a: '_ldap._tcp.dc._msdcs.<domain> (SRV).' },
    { q: 'What does Test-ComputerSecureChannel check?', a: 'That the member\'s machine account password matches AD, i.e. the secure channel works.' },
    { q: 'Domain users fail on win01 but local accounts work. Name two possible causes.', a: 'win01 cannot find or reach a DC (DNS, firewall), or its secure channel is broken.' },
    { q: 'Why grant rights to groups instead of users?', a: 'Access is managed in one place (group membership) instead of on every server.' },
  ],
};

export const KERBEROS_PRIMER: Primer = {
  oneLiner: '**Kerberos** lets you prove who you are once (with your password) and then use **tickets** to log in to services without sending your password again. A central **KDC** issues the tickets; clocks must agree within 5 minutes, and the KDC is found through DNS.',
  analogy: `
A festival wristband. At the entrance you show your ID once (your password to the KDC) and get a wristband (the **TGT**, ticket-granting ticket) valid for the day. At each stage you show the wristband at a booth (the KDC again) and get a ticket for that specific stage (a **service ticket**), which the stage staff can check without calling the entrance.

Tickets have times printed on them. If a stage's clock is very wrong, every ticket looks expired or not yet valid (**clock skew**).`,
  ideas: [
    {
      title: 'Principals and realms',
      explain: 'Every user and service is a **principal** in a **realm**: alice@CORP.LAB is a user, host/srv01.corp.lab@CORP.LAB is the SSH service on srv01. Realm names are written in capitals.',
      example: 'On ns1 (the KDC), `kadmin.local -q "listprincs"` lists alice@CORP.LAB, host/srv01.corp.lab@CORP.LAB and krbtgt/CORP.LAB@CORP.LAB (the key the KDC uses for TGTs).',
    },
    {
      title: 'kinit gets a TGT, klist shows your tickets',
      explain: '`kinit` asks the KDC for a TGT using your password. `klist` lists your tickets and their expiry. `kdestroy` throws them away.',
      example: '```\n$ kinit\nPassword for alice@CORP.LAB:\n$ klist\nDefault principal: alice@CORP.LAB\n... krbtgt/CORP.LAB@CORP.LAB\n```\nBefore kinit, klist says "No credentials cache found".',
    },
    {
      title: 'Services prove themselves with a keytab',
      explain: 'A service stores its key in a **keytab** file. It decrypts service tickets with it. The key version (**kvno**) in the keytab must match the KDC\'s.',
      example: 'srv01\'s /etc/krb5.keytab holds host/srv01.corp.lab. If the key is changed on the KDC but the old keytab stays on srv01, Kerberos SSH logins fail while passwords still work.',
    },
    {
      title: 'DNS SRV records and the clock',
      explain: 'Clients find the KDC with `_kerberos._udp.<domain>` SRV records. Clocks must be within 5 minutes of the KDC.',
      example: '`host -t SRV _kerberos._udp.corp.lab` → ns1.corp.lab port 88. A client clock 10 minutes off gets "Clock skew too great" from kinit.',
    },
  ],
  walkthrough: {
    title: 'alice logs in to srv01 with Kerberos instead of a password',
    steps: [
      { label: 'Find the KDC', detail: 'ws01 looks up _kerberos._udp.corp.lab and finds ns1.corp.lab:88.' },
      { label: 'Get a TGT (AS exchange)', detail: '`kinit`: alice types her password once; the KDC returns a TGT encrypted so only she can use it.' },
      { label: 'Get a service ticket (TGS exchange)', detail: 'ssh needs host/srv01.corp.lab. ws01 shows the TGT to the KDC and receives a ticket for that service.' },
      { label: 'Present it to srv01', detail: 'ssh sends the ticket (gssapi-with-mic). sshd decrypts it with the key in /etc/krb5.keytab and knows it is alice.' },
      { label: 'Logged in, no password', detail: '`klist` now shows both tickets: the TGT and host/srv01.corp.lab.' },
    ],
  },
  misconceptions: [
    { myth: 'Kerberos sends my password to every service.', truth: 'The password is used once, to get the TGT. Services only see tickets.' },
    { myth: 'Clock differences only matter for logs.', truth: 'Tickets carry timestamps; a skew over 5 minutes makes authentication fail.' },
    { myth: 'If kinit works, logins to every service will work.', truth: 'Each service also needs a correct keytab and principal name; a stale keytab fails only that service.' },
  ],
  checks: [
    { q: 'What does a TGT let you do?', a: 'Ask the KDC for service tickets without typing your password again.' },
    { q: 'Which port does the KDC listen on?', a: '88 (UDP and TCP).' },
    { q: 'kinit says "Clock skew too great". What do you fix?', a: 'The client\'s (or KDC\'s) time: they must be within 5 minutes (NTP).' },
    { q: 'Where does a service keep its Kerberos key?', a: 'In a keytab file, e.g. /etc/krb5.keytab.' },
  ],
};

export const DOCKER_PRIMER: Primer = {
  oneLiner: 'A **container** is a process running with its own view of files and network, started from an **image**. Docker connects containers to a private bridge network, and **publishing a port** (`-p 8080:80`) is what makes a container reachable from outside the host.',
  analogy: `
An image is a sealed meal kit with the recipe; a container is one meal cooked from it. You can cook many meals from one kit, and throwing a meal away does not change the kit. Anything you want to keep (the leftovers) goes in a labelled box in the fridge: a **volume**.

Each container lives in a flat inside an apartment block (the docker bridge network). The block has one street door (the host's address); **publishing** a port puts a sign on the street door: "visitors for 8080, go to flat 172.17.0.2 door 80".`,
  ideas: [
    {
      title: 'Images and containers',
      explain: 'An **image** is read-only layers (the OS files, the application). A **container** adds a writable layer and runs a process. Removing the container removes the writable layer.',
      example: '`docker run -d --name web nginx:1.25` starts a container from the nginx image. `docker ps` shows it; `docker rm -f web` deletes it and any file written inside it.',
    },
    {
      title: 'Container networking: bridge and published ports',
      explain: 'By default containers get a private address on the docker0 bridge (172.17.0.0/16), reachable from the host only. `-p HOSTPORT:CONTAINERPORT` adds NAT rules so the host forwards connections.',
      example: '`docker run -d -p 8080:80 nginx` → http://<host>:8080/ reaches nginx inside. Without `-p`, curl from another machine gets "Connection refused".',
    },
    {
      title: 'The app must listen on 0.0.0.0 inside the container',
      explain: 'Inside the container, "localhost" is the container itself. An app listening only on 127.0.0.1 cannot be reached through the published port.',
      example: 'A Flask app started with the default host 127.0.0.1 works from `docker exec` but returns "Connection reset" through -p 5000:5000. Start it with `--host 0.0.0.0`.',
    },
    {
      title: 'Logs and state',
      explain: '`docker logs` shows what the process wrote to stdout/stderr; `docker inspect` shows configuration and exit codes; data that must survive goes in **volumes**.',
      example: 'A database container keeps restarting: `docker logs db` shows "data directory has wrong ownership"; `docker inspect db` shows the volume mount and RestartCount.',
    },
  ],
  walkthrough: {
    title: 'Publishing a web container and reaching it from another machine',
    steps: [
      { label: 'Start it', detail: '`docker run -d --name web -p 8080:80 nginx:1.25`. Docker pulls the image if needed and starts nginx in a new container.' },
      { label: 'Check it runs', detail: '`docker ps` shows `0.0.0.0:8080->80/tcp` in the PORTS column.' },
      { label: 'Test on the host', detail: '`curl -I http://localhost:8080/` → 200. This proves the container and the port mapping.' },
      { label: 'Test from another machine', detail: 'curl http://<host>:8080/ from a client. If it fails while the host test works, look at the host firewall and the path, not at the container.' },
      { label: 'Read the logs', detail: '`docker logs web` shows each request line nginx logged.' },
    ],
  },
  misconceptions: [
    { myth: 'Files changed inside a container are saved.', truth: 'Only until the container is removed. Use volumes for data that must persist.' },
    { myth: 'EXPOSE in the Dockerfile publishes the port.', truth: 'EXPOSE is documentation. Only `-p` (or `ports:` in Compose) publishes a port on the host.' },
    { myth: 'A container is a small virtual machine.', truth: 'It is a process on the host\'s kernel with isolated namespaces; there is no separate kernel.' },
  ],
  checks: [
    { q: 'What does `-p 8080:80` mean?', a: 'Connections to port 8080 on the host are forwarded to port 80 in the container.' },
    { q: 'An app in a container listens on 127.0.0.1:5000. Can clients reach it through -p 5000:5000?', a: 'No: it must listen on 0.0.0.0 inside the container.' },
    { q: 'Where does important data go so it survives `docker rm`?', a: 'In a volume (or a bind mount).' },
    { q: 'Which command shows a container\'s output?', a: '`docker logs <container>`' },
  ],
};
