// Operate & recover guide: name resolution (client resolver and the BIND
// server on ns1) and the transport layer (sockets) everything rides on.

import type { ServiceGuide } from '../types';

export const TRANSPORT_GUIDE: ServiceGuide = {
  purpose:
    'DNS turns names into addresses, and almost every other service fails when it breaks, usually with a message that blames that service ("Could not resolve hostname", "Could not resolve host", a domain login error). This lesson covers both halves: the **client resolver** (glibc reading `/etc/nsswitch.conf`, `/etc/hosts` and `/etc/resolv.conf`, or systemd-resolved, or the Windows DNS Client) and an **authoritative server** (BIND `named` on ns1). Because DNS rides on UDP/TCP port 53, it also covers how to read sockets with `ss`, which applies to every service.',
  architecture: [
    { q: 'What does it accomplish?', a: 'Maps names to addresses (A, AAAA), addresses to names (PTR), and services to hosts (SRV, MX). In the lab ns1 is **authoritative** for `corp.lab`: it answers from its own zone file and does not recurse (`recursion requested but not available`).' },
    { q: 'How does it work internally?', a: 'On the client, a program calls `getaddrinfo()`. glibc consults `/etc/nsswitch.conf` (`hosts: files dns`): first `/etc/hosts`, then DNS using the servers, search list and options in `/etc/resolv.conf`. With systemd-resolved, resolv.conf points at the local stub `127.0.0.53` and resolved forwards to per-link DNS servers (`resolvectl status`). On the server, `named` loads each zone from its file at start and on `rndc reload`; a zone with a syntax error is **not loaded** and the server answers SERVFAIL for it.' },
    { q: 'Which protocols does it use?', a: 'DNS (RFC 1034/1035) over UDP; TCP for large answers and zone transfers; EDNS(0); DNSSEC optionally. The transport layer below is TCP (RFC 9293: handshake, sequence numbers, retransmission, RST) and UDP (RFC 768: no handshake; a closed port answers with ICMP port unreachable).' },
    { q: 'Which ports and transport?', a: 'UDP and TCP 53 on the server; `rndc` control channel TCP 953 on localhost; clients use random high source ports. Firewalls must allow **both** UDP and TCP 53 to the server, and the replies back (stateful `ct state established`).' },
    { q: 'Which processes and OS components implement it?', a: 'Client: glibc resolver (no daemon), optionally `systemd-resolved` (`resolvectl`), `nscd`; Windows **DNS Client** service (Dnscache) with its own cache (`ipconfig /displaydns`). Server: `named` (BIND 9, unit `named.service`, alias `bind9.service`), `rndc`, `named-checkconf`, `named-checkzone`. Windows Server: **DNS Server** service (dnsmgmt.msc). pfSense: Unbound (DNS Resolver). Docker: embedded DNS at 127.0.0.11 on user-defined networks.' },
    { q: 'Which other services does it depend on?', a: 'IP reachability between client and server (routing, firewalls), the zone file being valid, the server process running and listening, and for recursive resolvers, upstream connectivity. Active Directory, Kerberos, SSH host verification, TLS certificates, mail and web all depend on DNS.' },
    { q: 'How do requests travel?', a: 'Client sends a UDP query (random source port, random 16-bit ID) to the first `nameserver` → server looks up its zones → answers with NOERROR + records, NXDOMAIN (name does not exist), or SERVFAIL (cannot answer, e.g. zone not loaded). No answer within `timeout` → the client retries (`attempts`) and tries the next nameserver. For a short name like `srv01`, the search list makes the client try `srv01.corp.lab` first.' },
    { q: 'How do authentication and authorisation work?', a: 'Classic DNS answers are **not authenticated**: anyone who can answer first, or edit `/etc/hosts`, can redirect a name. DNSSEC signs zones; TSIG keys authenticate zone transfers and dynamic updates; `allow-query`, `allow-transfer` and `allow-recursion` in named.conf control who may ask what. AD-integrated zones use secure dynamic updates (Kerberos).' },
    { q: 'How does it start at boot?', a: '`named.service` starts after `network.target` and pulls in `nss-lookup.target`. It loads every zone; failures are logged but named still starts. Clients need nothing to start (glibc reads resolv.conf per lookup), except systemd-resolved, NetworkManager or resolvconf if they generate resolv.conf.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'Clients get no answer → timeouts → "Temporary failure in name resolution" (EAI_AGAIN) everywhere at once, while everything still works by IP. With two nameservers in resolv.conf, clients fail over after the timeout (slow but working). The unit has `Restart=on-failure`.' },
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
        { task: 'Is named running?', command: 'systemctl status named', explain: 'Look for `active (running)` and "zone corp.lab/IN: loaded serial N" in the journal lines.', sim: true },
        { task: 'Is it listening?', command: 'ss -tulnp', explain: '`UNCONN ... 0.0.0.0:53` (UDP) and `LISTEN ... 0.0.0.0:53` (TCP) owned by named; 127.0.0.1:953 for rndc.', sim: true },
        { task: 'Validate a zone before loading it', command: 'named-checkzone corp.lab /etc/bind/db.corp.lab', explain: 'Prints "loaded serial N" and `OK`, or the line number of the error.', sim: true },
        { task: 'Reload zones', command: 'sudo rndc reload\nsudo systemctl reload named', explain: 'Re-reads changed zone files without dropping the server. "server reload successful" only means the command was accepted; check the journal for per-zone results.', sim: true },
        { task: 'Restart', command: 'sudo systemctl restart named', explain: 'Needed after changing listen addresses or for a hung server.', risk: 'Short outage for every client; the cache (on recursive servers) is lost.', sim: true },
        { task: 'Logs', command: 'journalctl -u named -n 20\njournalctl -u named -b -p err', explain: 'Zone load results and errors.', sim: true },
        { task: 'Enable at boot / dependencies', command: 'systemctl is-enabled named\nsystemctl list-dependencies named', explain: 'Disabled named survives today but not the next reboot.', sim: true },
        { task: 'Test answers directly', command: 'dig @10.0.10.53 srv01.corp.lab\ndig @127.0.0.1 srv01.corp.lab', explain: 'Asking the server explicitly separates "server broken" from "path/client broken".', sim: true },
      ],
    },
    {
      platform: 'Linux clients',
      tasks: [
        { task: 'What will programs get?', command: 'getent hosts srv01.corp.lab', explain: 'Uses the same path as ssh/curl (nsswitch, /etc/hosts, DNS). No output = failed.', sim: true },
        { task: 'What does DNS say?', command: 'dig srv01.corp.lab', explain: 'Shows `status:` (NOERROR/NXDOMAIN/SERVFAIL), the answering server, and timing. Timeouts print "communications error ... timed out".', sim: true },
        { task: 'Which resolver configuration is in effect?', command: 'ls -l /etc/resolv.conf\ncat /etc/resolv.conf', explain: 'A symlink into /run/systemd/resolve means systemd-resolved manages it.', sim: true },
        { task: 'systemd-resolved hosts', command: 'resolvectl status\nresolvectl query srv01.corp.lab\nsudo resolvectl flush-caches\nsudo systemctl restart systemd-resolved', explain: 'Per-link DNS servers and domains; queries through the stub; cache flush; restart only if resolved itself misbehaves.' },
        { task: 'Sockets of any service', command: 'ss -tlnp\nss -tan', explain: '`LISTEN` = waiting for connections; `ESTAB` = open; `SYN-SENT` stuck = no answer (filtered); many `TIME-WAIT` = normal after closes.', sim: true },
      ],
    },
    {
      platform: 'RHEL',
      tasks: [
        { task: 'BIND service', command: 'systemctl status named\nnamed-checkconf /etc/named.conf\nsudo rndc reload', explain: 'Zone files live in /var/named/ and must be readable by the `named` group; SELinux context `named_zone_t` (restorecon).' },
        { task: 'Client resolver', command: 'nmcli device show eth0 | grep DNS\nsudo nmcli connection modify eth0 ipv4.dns 10.0.10.53 && sudo nmcli connection up eth0', explain: 'NetworkManager writes /etc/resolv.conf; change DNS in the profile.' },
      ],
    },
    {
      platform: 'Windows Server 2019/2022, Windows 10/11',
      tasks: [
        { task: 'Resolve and inspect', command: 'Resolve-DnsName srv01.corp.lab\nResolve-DnsName srv01.corp.lab -Server 10.0.10.53\nnslookup srv01.corp.lab', explain: '`Resolve-DnsName` uses the DNS Client path (including the hosts file and cache); `-Server` asks one server directly.' },
        { task: 'Client cache', command: 'ipconfig /displaydns\nipconfig /flushdns\nClear-DnsClientCache', explain: 'Negative answers are cached too; flush after fixing a record.' },
        { task: 'Client DNS servers', command: 'Get-DnsClientServerAddress\nSet-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses 10.0.10.53', explain: 'Domain members must use the domain controllers\' DNS only.' },
        { task: 'DNS Server role', command: 'Get-Service DNS\nRestart-Service DNS\ndnscmd /zoneinfo corp.lab', explain: 'Restarting the DNS Server service on a DC briefly stops name resolution for the whole domain.', risk: 'Prefer reloading a zone (`dnscmd /zonereload`).' },
      ],
    },
    {
      platform: 'pfSense / Docker',
      tasks: [
        { task: 'pfSense DNS Resolver', command: 'Services > DNS Resolver; Status > Services > unbound (restart)\nDiagnostics > DNS Lookup', explain: 'Unbound config is generated into /var/unbound/unbound.conf; host overrides answer local names.' },
        { task: 'Docker containers', command: 'docker exec web cat /etc/resolv.conf\ndocker exec web getent hosts db', explain: 'On user-defined networks containers use the embedded DNS 127.0.0.11, which resolves container/service names; the default bridge copies the host\'s resolv.conf.' },
      ],
    },
  ],
  actions: [
    { action: 'rndc reload / systemctl reload named', when: 'After editing zone files (with the serial increased) or named.conf zone statements.', effect: 'Reloads changed zones; the server keeps answering. A zone with errors is dropped while the others keep working.', risk: 'Low, but always run `named-checkzone` first: a bad file takes the whole zone offline (SERVFAIL).' },
    { action: 'systemctl restart named', when: 'Changing listen-on/options, or named is hung or failed.', effect: 'Full stop and start; all zones loaded fresh.', risk: 'Every client loses DNS for the duration; recursive caches are emptied.' },
    { action: 'Flush client caches (resolvectl flush-caches, ipconfig /flushdns)', when: 'After fixing a record that clients cached (including negative answers).', effect: 'Next lookup goes to the server.', risk: 'None.' },
    { action: 'Restart the client network / reboot', when: 'Almost never for DNS problems.', effect: 'May regenerate resolv.conf from DHCP or the manager.', risk: 'Disconnects sessions and hides the real cause; fix the configuration source instead.' },
  ],
  workflow: [
    { question: '1. Does it work by IP? (Is this really a DNS problem?)', command: 'ssh 10.0.20.10 hostname\ncurl -I http://10.0.20.10/', healthy: 'srv01\nHTTP/1.1 200 OK', broken: 'Fails by IP too → not DNS: go to the IP networking or service guide.', next: 'Works by IP, fails by name → DNS. Step 2.', sim: true },
    { question: '2. What does the system resolver return?', command: 'getent hosts srv01.corp.lab', healthy: '10.0.20.10      srv01.corp.lab', broken: 'No output = lookup failed. A **wrong** address = a stale /etc/hosts entry or a wrong DNS record (step 3 tells which).', next: 'Step 3.', sim: true },
    { question: '3. Is /etc/hosts overriding DNS?', command: 'grep srv01 /etc/hosts\ncat /etc/nsswitch.conf', healthy: '(no srv01 line)\nhosts:          files dns', broken: 'A line for srv01 with an old address explains why only this host is wrong; `dig` will show the correct DNS answer because dig ignores /etc/hosts.', next: 'Remove the stale entry, or step 4.', sim: true },
    { question: '4. Which server does the client ask?', command: 'cat /etc/resolv.conf', healthy: 'search corp.lab\nnameserver 10.0.10.53', broken: 'Wrong or unreachable nameserver (typo, public resolver that does not know corp.lab), missing search domain (short names fail).', next: 'Fix the source of resolv.conf; step 5.', sim: true },
    { question: '5. Does the server answer, and with what status?', command: 'dig srv01.corp.lab', healthy: ';; ->>HEADER<<- opcode: QUERY, status: NOERROR\n;; ANSWER SECTION:\nsrv01.corp.lab.  3600  IN  A  10.0.20.10', broken: '**timed out / no servers could be reached** → server down, firewall drop or no route (step 6). **SERVFAIL** → server reachable but zone not loaded (step 7). **NXDOMAIN** → the name does not exist in the zone (record missing or typo).', next: 'Branch on the status.', sim: true },
    { question: '6. Timeout: is named running, listening and reachable?', command: 'systemctl status named\nss -ulnp\ndig @127.0.0.1 srv01.corp.lab', healthy: 'Active: active (running)\nUNCONN 0 0 0.0.0.0:53 ... named\nstatus: NOERROR', broken: 'named stopped/failed → start it and read why it stopped. Answers locally but not remotely → firewall on ns1 (`nft list ruleset`) or the path (`ping 10.0.10.53`, `tcpdump -n -i eth0 port 53` on ns1).', next: 'Fix the firewall rule or service.', sim: true },
    { question: '7. SERVFAIL: did the zone load?', command: 'journalctl -u named -n 20\nnamed-checkzone corp.lab /etc/bind/db.corp.lab', healthy: 'zone corp.lab/IN: loaded serial 2026101901\nOK', broken: '"dns_master_load: ... bad dotted quad" / "not loaded due to errors" → fix the record, increase the serial, `rndc reload`.', next: 'Verify from a client.', sim: true },
    { question: '8. Is the transport layer healthy for the target service?', command: 'ss -tan\nnc -zv srv01.corp.lab 22', healthy: 'Connection to srv01.corp.lab (10.0.20.10) 22 port [tcp/ssh] succeeded!', broken: 'Refused (RST: nothing listening), timed out (dropped), stuck `SYN-SENT` in ss on the client.', next: 'Continue with the service\'s own guide.', sim: true },
  ],
  failures: [
    { symptom: 'Temporary failure in name resolution / no servers could be reached', causes: ['named stopped or not listening', 'Firewall on the DNS server drops port 53', 'Wrong or unreachable nameserver in resolv.conf'], diagnose: ['dig srv01.corp.lab', 'cat /etc/resolv.conf', 'systemctl status named; ss -ulnp (server)', 'nft list ruleset (server)'], fix: 'Start named / fix the firewall rule / correct the resolver source (DHCP option, netplan, NM profile).', verify: 'dig +short srv01.corp.lab' },
    { symptom: 'status: SERVFAIL for every name in the zone', causes: ['Zone file syntax error; named dropped the zone on reload'], diagnose: ['journalctl -u named -n 20', 'named-checkzone corp.lab /etc/bind/db.corp.lab'], fix: 'Fix the record, increase the serial, `rndc reload`.', verify: 'dig srv01.corp.lab (NOERROR)' },
    { symptom: 'Name or service not known (NXDOMAIN)', causes: ['Record missing or misspelt', 'Short name without the search domain'], diagnose: ['dig srv01.corp.lab', 'grep search /etc/resolv.conf'], fix: 'Add/correct the record (serial!) or the search list.', verify: 'getent hosts srv01' },
    { symptom: 'Resolves to an old address on one host only', causes: ['Stale /etc/hosts entry', 'Client cache (systemd-resolved, Windows DNS Client)'], diagnose: ['getent hosts srv01.corp.lab vs dig +short srv01.corp.lab', 'grep srv01 /etc/hosts', 'ipconfig /displaydns'], fix: 'Remove the hosts entry; flush the cache.', verify: 'getent hosts srv01.corp.lab' },
    { symptom: 'Changes to /etc/resolv.conf are lost', causes: ['File generated by systemd-resolved, NetworkManager, resolvconf or dhclient'], diagnose: ['ls -l /etc/resolv.conf', 'head -3 /etc/resolv.conf'], fix: 'Change the DNS servers at the source (netplan, nmcli, DHCP server option).', verify: 'resolv.conf after reconnect/reboot' },
    { symptom: 'Updates visible on the primary but not on secondaries', causes: ['Serial not increased'], diagnose: ['dig @primary corp.lab SOA +short', 'dig @secondary corp.lab SOA +short'], fix: 'Increase the serial and reload.', verify: 'Both servers report the same serial' },
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
