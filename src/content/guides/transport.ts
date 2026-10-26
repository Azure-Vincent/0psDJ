// Operate & recover guide: name resolution (client resolver and the BIND
// server on ns1) and the transport layer (sockets) everything rides on.

import type { ServiceGuide } from '../types';

export const TRANSPORT_GUIDE: ServiceGuide = {
  purpose:
    'DNS turns names into addresses, and when it breaks, almost every other service fails with it. The error messages usually blame the service you were using ("Could not resolve hostname", "Could not resolve host", a domain logon error), which is why DNS problems can be confusing at first. This guide covers both sides: the **client resolver**, which asks the questions (glibc reading `/etc/nsswitch.conf`, `/etc/hosts` and `/etc/resolv.conf`, or systemd-resolved, or the Windows DNS Client), and an **authoritative server**, which holds the answers (BIND `named` on ns1). Because DNS travels over UDP and TCP port 53, the guide also shows how to read sockets with `ss`, a skill you will use for every service.',
  architecture: [
    { q: 'What does it do?', a: 'DNS answers questions such as "which address belongs to this name?" (A records for IPv4, AAAA for IPv6), "which name belongs to this address?" (PTR) and "which host offers this service?" (SRV, MX). In the lab, ns1 is **authoritative** for `corp.lab`: it answers from its own zone file. It does not look up other names on your behalf (it does not **recurse**), which dig reports as `recursion requested but not available`.' },
    { q: 'How does it work inside?', a: 'On the client, a program calls `getaddrinfo()`. glibc reads `/etc/nsswitch.conf` (`hosts: files dns`) and checks `/etc/hosts` first, then asks DNS using the servers, search list and options in `/etc/resolv.conf`. On systems with systemd-resolved, resolv.conf points at a small local forwarder, `127.0.0.53`, which passes questions on to the real DNS servers of each network link (`resolvectl status` shows them). On the server, `named` reads each zone from its file when it starts and when you run `rndc reload`. A zone file with a syntax error is **not loaded** at all, and the server then answers SERVFAIL for every name in that zone.' },
    { q: 'Which protocols does it use?', a: 'DNS itself (RFC 1034/1035), normally over UDP; over TCP for large answers and zone transfers; with the EDNS(0) extension, and optionally signed with DNSSEC. Underneath are the two transport protocols from this lesson: TCP (RFC 9293: handshake, sequence numbers, resending, RST) and UDP (RFC 768: no handshake; a closed port answers with ICMP port unreachable).' },
    { q: 'Which ports does it use?', a: 'UDP and TCP port 53 on the server. The `rndc` control channel uses TCP 953, on localhost only. Clients send from random high source ports. A firewall in front of a DNS server must allow **both** UDP and TCP 53, and let the replies back out (a stateful rule such as `ct state established`).' },
    { q: 'Which processes and system components are involved?', a: 'On clients: the glibc resolver (a library, not a running service), optionally `systemd-resolved` (managed with `resolvectl`) or `nscd`, and on Windows the **DNS Client** service (Dnscache), which keeps its own cache (`ipconfig /displaydns`). On servers: `named` (BIND 9; unit `named.service`, also called `bind9.service`), with the tools `rndc`, `named-checkconf` and `named-checkzone`. Windows Server has the **DNS Server** service (dnsmgmt.msc); pfSense uses Unbound (its "DNS Resolver"); Docker runs a small built-in DNS server at 127.0.0.11 on user-defined networks.' },
    { q: 'What does it depend on?', a: 'IP connectivity between client and server in both directions (routing and firewalls, from the [IP networking lesson](#/lesson/ipnet/what)), a valid zone file, the server process running and listening, and for servers that recurse, a working connection to the servers they ask in turn. Many other services depend on DNS: Active Directory, Kerberos, SSH host key checking, TLS certificates, mail and the web.' },
    { q: 'How does a question travel?', a: 'The client sends a UDP query, from a random source port and with a random 16-bit ID, to the first `nameserver` in resolv.conf. The server looks the name up in its zones and answers with NOERROR plus the records, NXDOMAIN (the name does not exist) or SERVFAIL (it cannot answer, for example because the zone did not load). If no answer arrives within `timeout`, the client tries again (`attempts`) and moves on to the next nameserver. For a short name such as `srv01`, the search list makes the client try `srv01.corp.lab` first.' },
    { q: 'Is there any authentication?', a: 'Classic DNS answers are **not authenticated**: whoever answers first, or whoever can edit `/etc/hosts`, can send a name somewhere else. DNSSEC adds signatures to zones; TSIG keys authenticate zone transfers and dynamic updates; `allow-query`, `allow-transfer` and `allow-recursion` in named.conf control who may ask what. Active Directory zones only accept secure dynamic updates, authenticated with Kerberos.' },
    { q: 'How does it start at boot?', a: '`named.service` starts after `network.target` and pulls in `nss-lookup.target`. It loads every zone; if one fails, the error is logged but named still starts and serves the others. Clients need nothing started (glibc reads resolv.conf for every lookup), unless systemd-resolved, NetworkManager or resolvconf generates resolv.conf for them.' },
    { q: 'What happens if the DNS server stops?', a: 'Clients get no answer, wait for the timeout, and report "Temporary failure in name resolution" (EAI_AGAIN), everywhere at once, while everything still works by IP address. With two nameservers in resolv.conf, clients switch to the second one after the timeout: slow, but working. The named unit has `Restart=on-failure`, so systemd restarts it after a crash.' },
  ],
  ports: [
    { port: '53', proto: 'UDP', purpose: 'DNS queries (most traffic)' },
    { port: '53', proto: 'TCP', purpose: 'Large answers, zone transfers, fallback when truncated' },
    { port: '953', proto: 'TCP (localhost)', purpose: 'rndc control channel to named' },
    { port: '127.0.0.53:53', proto: 'UDP/TCP', purpose: 'systemd-resolved stub listener (clients)' },
  ],
  processes: [
    { name: 'named', platform: 'Debian/Ubuntu (bind9 package), RHEL (bind, unit named.service)', role: 'Authoritative and/or recursive DNS server' },
    { name: 'glibc resolver', platform: 'Linux clients', role: 'Reads nsswitch.conf, /etc/hosts, resolv.conf for every lookup (no cache)' },
    { name: 'systemd-resolved', platform: 'Ubuntu, Fedora (default)', role: 'Caching stub at 127.0.0.53; `resolvectl`' },
    { name: 'Dnscache (DNS Client)', platform: 'Windows 10/11, Server', role: 'Client cache; `ipconfig /displaydns`, `/flushdns`' },
    { name: 'DNS (DNS Server)', platform: 'Windows Server', role: 'AD-integrated zones, dnsmgmt.msc' },
  ],
  dependencies: {
    title: 'Name resolution: what "ssh srv01" needs before any packet reaches srv01',
    rows: [
      { label: 'Program', nodes: [{ id: 'app', label: 'ssh / curl', sub: 'getaddrinfo()', kind: 'client' }] },
      { label: 'Client', nodes: [{ id: 'nss', label: 'nsswitch.conf', sub: 'hosts: files dns', kind: 'data' }, { id: 'hosts', label: '/etc/hosts', sub: 'checked first', kind: 'data' }, { id: 'rconf', label: 'resolv.conf', sub: 'nameserver, search', kind: 'data' }] },
      { label: 'Network', nodes: [{ id: 'path', label: 'Route to ns1', sub: 'and back', kind: 'network' }, { id: 'fw', label: 'Firewalls', sub: 'udp+tcp 53', kind: 'network' }] },
      { label: 'Server', nodes: [{ id: 'named', label: 'named running', sub: 'listening :53', kind: 'service' }, { id: 'zone', label: 'Zone loaded', sub: 'db.corp.lab valid', kind: 'data' }] },
    ],
    edges: [['app', 'nss'], ['nss', 'hosts'], ['nss', 'rconf'], ['rconf', 'path'], ['path', 'fw'], ['fw', 'named'], ['named', 'zone']],
  },
  sequence: {
    title: 'getent hosts srv01.corp.lab on ws01',
    lanes: [{ id: 'c', label: 'ws01', sub: 'glibc' }, { id: 's', label: 'ns1', sub: 'named' }],
    steps: [
      { from: 'c', to: 'c', label: 'check /etc/hosts', note: 'A stale entry here wins over DNS: the cause of "it resolves to the old address".' },
      { from: 'c', to: 's', label: 'UDP 53: A? srv01.corp.lab', note: 'No route, firewall drop or named down → timeout → "Temporary failure in name resolution".' },
      { from: 's', to: 's', label: 'look up zone corp.lab', note: 'Zone failed to load → SERVFAIL (also reported as a temporary failure).' },
      { from: 's', to: 'c', label: 'NOERROR A 10.0.20.10', note: 'NXDOMAIN → "Name or service not known": the name really does not exist (typo, missing record).' },
    ],
  },
  files: [
    { path: '/etc/resolv.conf', platform: 'Linux', kind: 'config', perms: 'root:root 0644 (or a symlink)', contains: '`nameserver` (up to 3), `search`/`domain`, `options timeout:2 attempts:2`.', accessed: 'By glibc on every lookup.', problems: 'Often **generated**: a symlink to `/run/systemd/resolve/stub-resolv.conf` (systemd-resolved), or written by NetworkManager, resolvconf or dhclient. Hand edits are then overwritten. Check `ls -l /etc/resolv.conf` and the header comment first. A typo in the address gives timeouts for every name.' },
    { path: '/etc/hosts', platform: 'Linux (Windows: C:\\Windows\\System32\\drivers\\etc\\hosts)', kind: 'config', perms: 'root:root 0644', contains: 'Static name → address lines.', accessed: 'Before DNS when nsswitch says `files dns`.', problems: 'Stale entries survive DNS changes indefinitely and only affect that host, which makes the problem look random.' },
    { path: '/etc/nsswitch.conf', platform: 'Linux', kind: 'config', perms: 'root:root 0644', contains: 'Lookup order per database (`hosts: files dns`, possibly `mdns4_minimal`, `resolve`, `myhostname`).', accessed: 'By glibc for every lookup.', problems: 'Removing `dns` makes only /etc/hosts work. Note that `dig` and `nslookup` ignore it (they query DNS directly), while `getent`, ssh and curl obey it.' },
    { path: '/etc/bind/named.conf, named.conf.options, named.conf.local', platform: 'Debian/Ubuntu (RHEL: /etc/named.conf)', kind: 'config', perms: 'root:bind 0644', contains: 'Options (listen-on, recursion, allow-query, forwarders) and `zone` statements naming each zone file.', accessed: 'At start and on `rndc reload`/`rndc reconfig`.', problems: 'A syntax error stops named from starting (check with `named-checkconf`). A wrong `file` path: "loading from master file ... failed: file not found" and the zone is not served.' },
    { path: '/etc/bind/db.corp.lab', platform: 'ns1 (zone files; RHEL: /var/named/)', kind: 'data', perms: 'root:bind 0644 (named must be able to read it)', contains: 'SOA (with the **serial**), NS, A, AAAA, CNAME records.', accessed: 'When the zone is loaded (start, reload).', problems: 'A bad record ("bad dotted quad") makes named reject the **whole zone** → SERVFAIL for every name in it. Forgetting to increase the serial means secondaries never pick up the change.' },
    { path: 'journal: journalctl -u named', platform: 'Linux', kind: 'log', contains: 'Zone loads ("loaded serial"), errors ("not loaded due to errors"), reloads.', accessed: 'Continuously.', problems: 'Query logging is off by default (`rndc querylog on` to enable temporarily).' },
    { path: '/lib/systemd/system/named.service', platform: 'Debian 12', kind: 'unit', contains: '`ExecStart=/usr/sbin/named $OPTIONS`, `ExecReload=/usr/sbin/rndc reload`, `Alias=bind9.service`.', accessed: 'Boot, daemon-reload.', problems: 'On older Debian/Ubuntu the unit is `bind9.service`; both names work on Debian 12.' },
    { path: '/run/systemd/resolve/resolv.conf, stub-resolv.conf', platform: 'Ubuntu, systemd-resolved', kind: 'runtime', contains: 'Generated lists of the real upstream servers, or just 127.0.0.53.', accessed: 'Regenerated when links change.', problems: 'Edit the source (netplan `nameservers`, NetworkManager profile, `/etc/systemd/resolved.conf`), not these files.' },
    { path: 'Event Viewer: Microsoft-Windows-DNS-Client/Operational; DNS Server log', platform: 'Windows', kind: 'eventlog', contains: 'Client resolution failures (often disabled by default); server zone load and AD-integration events (4013 at boot when AD is not ready).', accessed: 'Continuously.', problems: 'Event 4013 on a DC after reboot means DNS waited for AD replication; persistent 4013 indicates replication problems.' },
  ],
  management: [
    {
      platform: 'Debian (BIND on ns1, the lab)',
      tasks: [
        { task: 'Is named running?', command: 'systemctl status named', explain: 'Look for `active (running)`, and in the log lines underneath for "zone corp.lab/IN: loaded serial N", which confirms the zone loaded.', sim: true },
        { task: 'Is it listening?', command: 'ss -tulnp', explain: '`-t` TCP, `-u` UDP, `-l` listening, `-n` numbers, `-p` processes. Expect `UNCONN ... 0.0.0.0:53` (UDP sockets show UNCONN because UDP has no connections) and `LISTEN ... 0.0.0.0:53` (TCP) owned by named, plus 127.0.0.1:953 for rndc.', sim: true },
        { task: 'Validate a zone before loading it', command: 'named-checkzone corp.lab /etc/bind/db.corp.lab', explain: 'Checks a zone file without loading it. Prints "loaded serial N" and `OK`, or the line number of the error. Run it before every reload.', sim: true },
        { task: 'Reload zones', command: 'sudo rndc reload\nsudo systemctl reload named', explain: 'Re-reads changed zone files while the server keeps answering. "server reload successful" only means named accepted the command; whether each zone actually loaded is written to the journal.', sim: true },
        { task: 'Restart', command: 'sudo systemctl restart named', explain: 'A full stop and start. Only needed after changing the addresses named listens on, or when it hangs.', risk: 'Short outage for every client; the cache (on recursive servers) is lost.', sim: true },
        { task: 'Logs', command: 'journalctl -u named -n 20\njournalctl -u named -b -p err', explain: 'The last 20 log lines, and all errors since boot: zone load results and problems.', sim: true },
        { task: 'Enable at boot / dependencies', command: 'systemctl is-enabled named\nsystemctl list-dependencies named', explain: 'A service that is running but not enabled works today and is gone after the next reboot.', sim: true },
        { task: 'Test answers directly', command: 'dig @10.0.10.53 srv01.corp.lab\ndig @127.0.0.1 srv01.corp.lab', explain: 'Asking one server directly (`@address`) separates "the server is broken" from "the path or the client is broken".', sim: true },
      ],
    },
    {
      platform: 'Linux clients',
      tasks: [
        { task: 'What will programs get?', command: 'getent hosts srv01.corp.lab', explain: 'Uses the same path as ssh and curl (nsswitch, /etc/hosts, then DNS). No output means the lookup failed.', sim: true },
        { task: 'What does DNS say?', command: 'dig srv01.corp.lab', explain: 'Shows the `status:` (NOERROR, NXDOMAIN or SERVFAIL), which server answered, and how long it took. If no server answers, dig prints "communications error ... timed out".', sim: true },
        { task: 'Which resolver configuration is in effect?', command: 'ls -l /etc/resolv.conf\ncat /etc/resolv.conf', explain: 'If `ls -l` shows a link into /run/systemd/resolve, systemd-resolved manages the file and hand edits will be overwritten.', sim: true },
        { task: 'systemd-resolved hosts', command: 'resolvectl status\nresolvectl query srv01.corp.lab\nsudo resolvectl flush-caches\nsudo systemctl restart systemd-resolved', explain: 'Shows the DNS servers and domains of each network link, sends a query through the local forwarder, clears its cache, and restarts it (only needed if systemd-resolved itself misbehaves).' },
        { task: 'Sockets of any service', command: 'ss -tlnp\nss -tan', explain: '`LISTEN`: waiting for connections. `ESTAB`: an open connection. A connection stuck in `SYN-SENT`: no answer to the SYN (probably filtered). Many `TIME-WAIT` entries are normal after connections close.', sim: true },
      ],
    },
    {
      platform: 'RHEL',
      tasks: [
        { task: 'BIND service', command: 'systemctl status named\nnamed-checkconf /etc/named.conf\nsudo rndc reload', explain: 'On RHEL, zone files live in /var/named/ and must be readable by the `named` group. SELinux also requires the file label `named_zone_t`; `restorecon` sets it.' },
        { task: 'Client resolver', command: 'nmcli device show eth0 | grep DNS\nsudo nmcli connection modify eth0 ipv4.dns 10.0.10.53 && sudo nmcli connection up eth0', explain: 'NetworkManager writes /etc/resolv.conf, so change the DNS server in the connection profile, not in the file.' },
      ],
    },
    {
      platform: 'Windows Server 2019/2022, Windows 10/11',
      tasks: [
        { task: 'Resolve and inspect', command: 'Resolve-DnsName srv01.corp.lab\nResolve-DnsName srv01.corp.lab -Server 10.0.10.53\nnslookup srv01.corp.lab', explain: '`Resolve-DnsName` takes the same path as applications (hosts file and cache included); with `-Server` it asks one DNS server directly.' },
        { task: 'Client cache', command: 'ipconfig /displaydns\nipconfig /flushdns\nClear-DnsClientCache', explain: 'Windows also caches "this name does not exist" answers, so flush the cache after fixing a record.' },
        { task: 'Client DNS servers', command: 'Get-DnsClientServerAddress\nSet-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses 10.0.10.53', explain: 'Shows and sets the DNS servers of each adapter. Computers in an Active Directory domain must use only the domain controllers as DNS servers.' },
        { task: 'DNS Server role', command: 'Get-Service DNS\nRestart-Service DNS\ndnscmd /zoneinfo corp.lab', explain: 'Checks and restarts the DNS Server role. Restarting it on a domain controller briefly stops name resolution for the whole domain.', risk: 'Prefer reloading a zone (`dnscmd /zonereload`).' },
      ],
    },
    {
      platform: 'pfSense / Docker',
      tasks: [
        { task: 'pfSense DNS Resolver', command: 'Services > DNS Resolver; Status > Services > unbound (restart)\nDiagnostics > DNS Lookup', explain: 'pfSense generates Unbound\'s configuration into /var/unbound/unbound.conf from the GUI settings. Host overrides make it answer for local names.' },
        { task: 'Docker containers', command: 'docker exec web cat /etc/resolv.conf\ndocker exec web getent hosts db', explain: 'On user-defined networks, containers use Docker\'s built-in DNS at 127.0.0.11, which knows the names of the other containers and services. On the default bridge network, containers get a copy of the host\'s resolv.conf instead.' },
      ],
    },
  ],
  actions: [
    { action: 'rndc reload / systemctl reload named', when: 'After editing a zone file (and increasing its serial) or the zone statements in named.conf.', effect: 'Loads the changed zones while the server keeps answering. A zone with errors is dropped; the other zones keep working.', risk: 'Low, but always run `named-checkzone` first: a bad file takes the whole zone offline (SERVFAIL).' },
    { action: 'systemctl restart named', when: 'After changing listen-on or other options, or when named hangs or has failed.', effect: 'A full stop and start; every zone is loaded fresh.', risk: 'Every client loses DNS while it restarts, and a recursive server loses its cache.' },
    { action: 'Flush client caches (resolvectl flush-caches, ipconfig /flushdns)', when: 'After fixing a record that clients may have cached, including "does not exist" answers.', effect: 'The next lookup goes to the server again.', risk: 'None.' },
    { action: 'Restart the client\'s networking, or reboot', when: 'Almost never the right answer for DNS problems.', effect: 'May regenerate resolv.conf from DHCP or the network manager.', risk: 'Disconnects sessions and can hide the real cause. Fix the place the configuration comes from instead.' },
  ],
  workflow: [
    { question: 'Does it work by IP address?', why: 'Before blaming DNS, make sure it really is DNS. If the service also fails when you use its IP address, the problem is in the network or the service itself, and fixing DNS would not help.', command: 'ssh 10.0.20.10 hostname\ncurl -I http://10.0.20.10/', healthy: 'srv01\nHTTP/1.1 200 OK', broken: 'It fails by IP too: this is not a DNS problem. Go to the [IP networking](#/lesson/ipnet/troubleshoot) guide or the service\'s own guide.', next: 'Works by IP but not by name: it is DNS. Go to step 2.', sim: true },
    { question: 'What does the system resolver return?', why: '`getent` uses exactly the same path as ssh and curl, so its answer is the one your applications get.', command: 'getent hosts srv01.corp.lab', healthy: '10.0.20.10      srv01.corp.lab', broken: 'No output: the lookup failed. A **wrong** address: either a stale /etc/hosts entry or a wrong DNS record. Step 3 tells which.', next: 'Go to step 3.', sim: true },
    { question: 'Is /etc/hosts overriding DNS?', why: 'With `hosts: files dns`, a matching line in /etc/hosts wins and DNS is never asked. A forgotten line there only affects this one host, which makes problems look random.', command: 'grep srv01 /etc/hosts\ncat /etc/nsswitch.conf', healthy: '(no srv01 line)\nhosts:          files dns', broken: 'A line for srv01 with an old address explains why only this host gets it wrong. `dig` will still show the correct DNS answer, because dig ignores /etc/hosts.', next: 'Remove the stale line. If there is none, go to step 4.', sim: true },
    { question: 'Which DNS server does the client ask?', why: 'The client can only get a right answer from a server that knows the zone and that it can reach.', command: 'cat /etc/resolv.conf', healthy: 'search corp.lab\nnameserver 10.0.10.53', broken: 'A wrong or unreachable nameserver (a typo, or a public resolver that knows nothing about corp.lab). A missing `search` line: short names such as `srv01` fail while full names work.', next: 'Fix the place resolv.conf comes from (DHCP, netplan, NetworkManager), then go to step 5.', sim: true },
    { question: 'Does the server answer, and with what status?', why: 'The `status:` field in dig\'s output sorts DNS problems into three different families, each with its own next step.', command: 'dig srv01.corp.lab', healthy: ';; ->>HEADER<<- opcode: QUERY, status: NOERROR\n;; ANSWER SECTION:\nsrv01.corp.lab.  3600  IN  A  10.0.20.10', broken: '**timed out / no servers could be reached**: the server is down, a firewall drops the query, or there is no route (step 6). **SERVFAIL**: the server is reachable but the zone did not load (step 7). **NXDOMAIN**: the name does not exist in the zone (a missing record or a typo).', next: 'Follow the branch that matches the status.', sim: true },
    { question: 'Timeout: is named running, listening and reachable?', why: 'A timeout means no answer came back at all. Asking the server from itself (127.0.0.1) splits the problem in two: is the server broken, or is the path to it broken?', command: 'systemctl status named\nss -ulnp\ndig @127.0.0.1 srv01.corp.lab', healthy: 'Active: active (running)\nUNCONN 0 0 0.0.0.0:53 ... named\nstatus: NOERROR', broken: 'named is stopped or failed: start it, and read in the journal why it stopped. It answers locally but not from clients: look at ns1\'s firewall (`nft list ruleset`) or the path (`ping 10.0.10.53`, and `tcpdump -n -i eth0 port 53` on ns1 to see whether queries arrive).', next: 'Fix the service or the firewall rule, then test again from a client.', sim: true },
    { question: 'SERVFAIL: did the zone load?', why: 'named refuses a whole zone if a single line in its file is wrong, and then answers SERVFAIL for every name in it.', command: 'journalctl -u named -n 20\nnamed-checkzone corp.lab /etc/bind/db.corp.lab', healthy: 'zone corp.lab/IN: loaded serial 2026101901\nOK', broken: 'Messages like "dns_master_load: ... bad dotted quad" or "not loaded due to errors": fix the bad record, increase the serial number, then run `rndc reload`.', next: 'Check the answer again from a client.', sim: true },
    { question: 'Does the connection to the target service work?', why: 'Once the name resolves, the remaining question is the one from the transport part of this lesson: can a TCP connection be made to the service\'s port?', command: 'ss -tan\nnc -zv srv01.corp.lab 22', healthy: 'Connection to srv01.corp.lab (10.0.20.10) 22 port [tcp/ssh] succeeded!', broken: 'Refused: a reset came back, nothing listens on that port. Timed out: the packets are dropped. A connection stuck in `SYN-SENT` in `ss` on the client: the SYN gets no answer (filtered).', next: 'Continue with the service\'s own guide.', sim: true },
  ],
  failures: [
    { symptom: 'Temporary failure in name resolution / no servers could be reached', causes: ['named stopped or not listening', 'Firewall on the DNS server drops port 53', 'Wrong or unreachable nameserver in resolv.conf'], diagnose: ['dig srv01.corp.lab', 'cat /etc/resolv.conf', 'systemctl status named; ss -ulnp (server)', 'nft list ruleset (server)'], fix: 'Depending on the cause: start named; fix the firewall rule on the DNS server; or correct the DNS server address where resolv.conf comes from (the DHCP option, netplan file or NetworkManager profile).', verify: 'dig +short srv01.corp.lab' },
    { symptom: 'status: SERVFAIL for every name in the zone', causes: ['Zone file syntax error; named dropped the zone on reload'], diagnose: ['journalctl -u named -n 20', 'named-checkzone corp.lab /etc/bind/db.corp.lab'], fix: 'Fix the bad record, increase the serial number in the SOA record, then run `rndc reload`.', verify: 'dig srv01.corp.lab (NOERROR)' },
    { symptom: 'Name or service not known (NXDOMAIN)', causes: ['Record missing or misspelt', 'Short name without the search domain'], diagnose: ['dig srv01.corp.lab', 'grep search /etc/resolv.conf'], fix: 'Add or correct the record (and increase the serial), or add the missing search domain.', verify: 'getent hosts srv01' },
    { symptom: 'Resolves to an old address on one host only', causes: ['Stale /etc/hosts entry', 'Client cache (systemd-resolved, Windows DNS Client)'], diagnose: ['getent hosts srv01.corp.lab vs dig +short srv01.corp.lab', 'grep srv01 /etc/hosts', 'ipconfig /displaydns'], fix: 'Remove the stale /etc/hosts line, and flush the client\'s DNS cache.', verify: 'getent hosts srv01.corp.lab' },
    { symptom: 'Changes to /etc/resolv.conf are lost', causes: ['File generated by systemd-resolved, NetworkManager, resolvconf or dhclient'], diagnose: ['ls -l /etc/resolv.conf', 'head -3 /etc/resolv.conf'], fix: 'The file is written by another program. Change the DNS servers where that program gets them from: netplan, the NetworkManager profile (nmcli), or the DHCP server\'s options.', verify: 'resolv.conf after reconnect/reboot' },
    { symptom: 'Updates visible on the primary but not on secondaries', causes: ['Serial not increased'], diagnose: ['dig @primary corp.lab SOA +short', 'dig @secondary corp.lab SOA +short'], fix: 'Secondary servers only copy a zone when its serial number goes up. Increase the serial and reload.', verify: 'Both servers report the same serial' },
  ],
  verification: [
    { check: 'Server healthy', command: 'systemctl is-active named; named-checkzone corp.lab /etc/bind/db.corp.lab', expect: 'active ... OK' },
    { check: 'Server answers locally', command: 'dig @127.0.0.1 srv01.corp.lab +short', expect: '10.0.20.10' },
    { check: 'Clients on every network resolve', command: 'getent hosts srv01.corp.lab (ws01, ws02, dev01)', expect: '10.0.20.10 / 2001:db8:20::10 srv01.corp.lab' },
    { check: 'Applications work by name', command: 'ssh srv01.corp.lab hostname; curl -I http://srv01.corp.lab/', expect: 'srv01 / HTTP/1.1 200 OK' },
    { check: 'Persistent after reboot', command: 'systemctl is-enabled named; cat /etc/resolv.conf', expect: 'enabled; correct nameserver from the configuration source' },
  ],
  refIds: ['dig', 'getent', 'resolvectl', 'nslookup-win', 'resolve-dnsname', 'ss', 'nc', 'named-checkzone', 'rndc', 'tcpdump', 'systemctl', 'journalctl', 'file:resolv.conf', 'file:hosts', 'file:nsswitch.conf', 'file:named.conf', 'file:zone-files', 'file:hosts-win', 'file:unbound-conf', 'proc:dns-resolver-fix', 'proc:bind-zone-change'],
};
