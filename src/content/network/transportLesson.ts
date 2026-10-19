import type { Lesson } from '../types';

export const TRANSPORT_LESSON: Lesson = {
  id: 'transport',
  moduleId: 'A',
  title: 'TCP, UDP and DNS',
  level: 'beginner',
  summary: 'Ports and sockets, the TCP connection lifecycle (handshake, sequence numbers, retransmission, teardown), UDP, and how a name becomes an address.',
  concepts: ['tcp.handshake', 'svc.listening', 'dns.resolution', 'dns.zone', 'net.icmp'],

  what: `
IP delivers packets between hosts. The **transport layer** delivers data between **programs** on those hosts, and **DNS** turns the names people type into the addresses IP needs.

### Ports and sockets
A **socket** is one endpoint of communication, identified by (protocol, IP address, port). A server program **binds** a listening socket, e.g. TCP 0.0.0.0:22 for sshd. A connection is identified by the 5-tuple *(protocol, source IP, source port, destination IP, destination port)*; the client's source port is an **ephemeral port** chosen by its kernel (32768–60999 on Linux). Well-known ports: 22 SSH, 53 DNS, 80/443 HTTP(S), 3389 RDP.

### TCP and UDP
| | TCP | UDP |
|---|---|---|
| Connection | 3-way handshake, explicit close | none |
| Reliability | sequence numbers, acknowledgements, retransmission | none (application decides) |
| Ordering / flow control | yes / receive window | no / no |
| Typical uses | SSH, HTTP, SMB, LDAP, RDP | DNS queries, NTP, DHCP, syslog, VoIP |
| When nothing listens | RST → "Connection refused" | ICMP port unreachable (or silence) |

### DNS in one sentence
Applications call \`getaddrinfo()\`; the **stub resolver** checks \`/etc/hosts\`, then asks the **recursive/authoritative DNS servers** in \`/etc/resolv.conf\` over UDP port 53 (TCP for large answers), trying search domains for short names.

> The simulator implements TCP's handshake, RST, SYN retransmission with exponential backoff, data segments with sequence/acknowledgement numbers and FIN teardown; UDP; ICMP port unreachable; and a glibc-style resolver talking to a BIND-style authoritative server. It does not model congestion control or window dynamics.
`,

  internals: `
### TCP connection establishment
1. **SYN**: the client picks a random Initial Sequence Number (ISN) and options (MSS, SACK, window scale, timestamps). Socket state SYN_SENT.
2. **SYN-ACK**: if a socket listens on that address and port, the server kernel replies with its own ISN and ack = client ISN + 1 (SYN_RECV). The application is not involved yet.
3. **ACK**: ack = server ISN + 1. Both sides ESTABLISHED; the connection waits in the listener's accept queue until the program calls accept().

If nothing listens, the server kernel answers the SYN with **RST, ACK** → ECONNREFUSED. If nothing answers at all, Linux retransmits the SYN after 1, 2, 4, 8, 16 and 32 s (\`net.ipv4.tcp_syn_retries = 6\`) and gives up after about 127 s → ETIMEDOUT. Applications usually set their own shorter timeout (\`ssh -o ConnectTimeout\`, \`curl -m\`, \`nc -w\`).

### Sequence numbers and acknowledgements
Every byte sent has a sequence number. A segment carrying *n* bytes at seq *s* is acknowledged by ack *s + n* ("I have everything before this byte"). SYN and FIN each consume one sequence number. Lost data is detected by missing acknowledgements and retransmitted; the receiver's **window** limits how much unacknowledged data may be in flight (flow control). tcpdump and Wireshark show **relative** sequence numbers (ISN = 0) by default.

### Closing
Each side closes its direction with **FIN**: FIN → ACK (often combined with the other side's FIN) → ACK. The side that closes first waits in **TIME_WAIT** (2 × MSL) so stray segments of the old connection cannot be mistaken for a new one. **RST** aborts a connection immediately (no listener, an application crash, or a firewall "reject with tcp reset").

### UDP
A UDP datagram is sent and forgotten: 8-byte header (ports, length, checksum), no handshake, no retransmission. Reliability, if needed, is the application's job: a DNS resolver retries after its timeout (\`options timeout:N attempts:N\` in resolv.conf). A datagram to a closed port normally produces **ICMP port unreachable**, which tells the resolver immediately to try the next server.

### Name resolution step by step (glibc)
1. \`/etc/nsswitch.conf\` → \`hosts: files dns\`: check **/etc/hosts** first; a match there wins, DNS is never asked.
2. Build candidates: if the name has fewer dots than \`ndots\` (default 1), append each **search** domain first (\`srv01\` → \`srv01.corp.lab.\`), otherwise try the name as-is first.
3. For each candidate, ask each **nameserver** in order, \`attempts\` times, waiting \`timeout\` seconds.
4. **NOERROR with an answer** → done. **NXDOMAIN** → next candidate. **Timeouts / SERVFAIL / unreachable server** → stop: EAI_AGAIN, "Temporary failure in name resolution". All candidates NXDOMAIN → "Name or service not known".

### The DNS server side
An **authoritative** server answers for zones it holds (flag *aa*): \`corp.lab\` on ns1, loaded from a zone file with an SOA record (serial, timers), NS and A/CNAME records. If the zone fails to load, the server answers **SERVFAIL**. A server that is not authoritative and does not recurse answers **REFUSED**. A **CNAME** answer is followed to the final A record (\`www.corp.lab → srv01.corp.lab → 10.0.20.10\`).

### Tools see different things
- \`dig\` asks a DNS server directly: no /etc/hosts, no search list unless \`+search\`.
- \`getent hosts\` uses NSS exactly like ssh/curl.
- \`nslookup\` applies the search list but ignores /etc/hosts.
When they disagree, the disagreement is the clue. The resolver tracer below runs the simulator's resolver step by step.
`,

  deployment: [
    {
      id: 'sockets',
      platform: 'Linux: sockets and TCP',
      summary: 'Start a throw-away TCP service, inspect sockets and connections, and capture a full TCP lifecycle. Run on a real VM (two hosts are best). Marked steps also work in the sandbox.',
      prerequisites: ['Two Linux machines (or two terminals), netcat-openbsd, tcpdump.'],
      steps: [
        { title: 'Start a listener', command: 'nc -l -k 0.0.0.0 9000', what: 'netcat binds TCP 0.0.0.0:9000 and prints what clients send.', why: 'A minimal server to observe binding, accepting and closing.', expected: '(waits for connections)' },
        { title: 'Inspect listening sockets', command: 'sudo ss -tlnp', what: 'Lists TCP listening sockets with owning processes.', why: '0.0.0.0 = all addresses; 127.0.0.1 = local only. No line = clients get "Connection refused".', expected: 'LISTEN 0 1 0.0.0.0:9000 0.0.0.0:* users:(("nc",pid=2210,fd=3))', simulated: true },
        { title: 'Capture while connecting', command: 'sudo tcpdump -i eth0 -n "tcp port 9000"\n# from the other host:\nprintf hello | nc -q1 server 9000', what: 'Shows SYN, SYN-ACK, ACK, the data segment, and the FIN exchange.', why: 'Seeing the handshake and teardown with your own data ties the theory to the wire.', expected: 'IP 10.0.10.25.51514 > 10.0.20.10.9000: Flags [S], seq 1520034, ... length 0\nIP 10.0.20.10.9000 > 10.0.10.25.51514: Flags [S.], seq 99102, ack 1520035, ... length 0\nIP 10.0.10.25.51514 > 10.0.20.10.9000: Flags [.], ack 1, ... length 0\nIP 10.0.10.25.51514 > 10.0.20.10.9000: Flags [P.], seq 1:6, ack 1, ... length 5\nIP 10.0.10.25.51514 > 10.0.20.10.9000: Flags [F.], seq 6, ack 1, ... length 0' },
        { title: 'Connection refused vs timed out', command: 'nc -zv -w 5 server 9001     # nothing listening\nnc -zv -w 5 server 3306     # dropped by a firewall', what: 'Two failure modes with different wire evidence.', why: 'Refused = an RST came back; timed out = nothing came back.', expected: 'nc: connect to server port 9001 (tcp) failed: Connection refused\nnc: connect to server port 3306 (tcp) failed: Connection timed out' },
        { title: 'See established connections', command: 'ss -tn state established', what: 'Lists established TCP connections with both endpoints.', why: 'Each line is one 5-tuple: useful to see who is connected to a service.', expected: 'Recv-Q Send-Q Local Address:Port Peer Address:Port\n0      0      10.0.20.10:22      10.0.10.25:51514', simulated: true },
      ],
    },
    {
      id: 'resolver',
      platform: 'Linux: resolver configuration',
      summary: 'Configure and verify how a Debian host resolves names. On Ubuntu, systemd-resolved manages /etc/resolv.conf (use resolvectl).',
      prerequisites: ['Debian 12 VM.'],
      steps: [
        { title: 'Read the resolver configuration', command: 'cat /etc/nsswitch.conf | grep hosts\ncat /etc/resolv.conf\ncat /etc/hosts', what: 'Source order, DNS servers/search domains/options, and static entries.', why: 'These three files fully determine what getaddrinfo() does.', expected: 'hosts:          files dns\nsearch corp.lab\nnameserver 10.0.10.53', simulated: true },
        { title: 'Resolve like an application', command: 'getent hosts srv01\ngetent hosts srv01.corp.lab', what: 'Uses NSS (files, then DNS with the search list).', why: 'This is what ssh, curl and ping will use.', expected: '10.0.20.10      srv01.corp.lab', simulated: true },
        { title: 'Ask DNS directly', command: 'dig srv01.corp.lab\ndig @10.0.10.53 srv01.corp.lab +short\ndig www.corp.lab', what: 'Shows status, flags (aa), the answering server and CNAME chains.', why: 'Separates "DNS is wrong" from "my host does something else".', expected: ';; ->>HEADER<<- opcode: QUERY, status: NOERROR\nwww.corp.lab.  3600 IN CNAME srv01.corp.lab.\nsrv01.corp.lab. 3600 IN A 10.0.20.10', simulated: true },
        { title: 'Tune timeouts', command: 'sudo nano /etc/resolv.conf\n\nsearch corp.lab\nnameserver 10.0.10.53\nnameserver 10.0.10.54\noptions timeout:2 attempts:2 rotate', what: 'Two servers, 2 s per try, 2 rounds, rotating the starting server.', why: 'The defaults (5 s, 2 attempts) make a dead first server cost 10 s per lookup.', expected: '' },
      ],
    },
    {
      id: 'windows-dns',
      platform: 'Windows',
      summary: 'Equivalent client-side checks.',
      prerequisites: ['Windows 10/11 or Server, PowerShell.'],
      steps: [
        { title: 'Resolve like an application', command: 'Resolve-DnsName srv01.corp.lab\nResolve-DnsName srv01.corp.lab -DnsOnly -Server 10.0.10.53', what: 'Uses the Windows DNS client (hosts file, cache, suffix search); -DnsOnly skips hosts and cache.', why: 'Same distinction as getent vs dig.', expected: 'Name             Type TTL  Section IPAddress\nsrv01.corp.lab   A    3600 Answer  10.0.20.10' },
        { title: 'Cache and sockets', command: 'Get-DnsClientCache | Select-Object -First 5\nipconfig /flushdns\nGet-NetTCPConnection -State Listen', what: 'DNS client cache, clearing it, and listening TCP sockets.', why: 'Windows caches negative and positive answers; stale cache entries survive DNS fixes until flushed or expired.', expected: 'Successfully flushed the DNS Resolver Cache.' },
      ],
    },
  ],

  configIntro: `
The transport layer is mostly configured by applications (which address and port to bind) and by a few kernel parameters; name resolution by three small files. The resolver tracer runs the simulator's resolver on the lab, so you can see each step for any name.
`,

  configFiles: [
    {
      platform: 'Linux',
      items: [
        { path: '/etc/nsswitch.conf', purpose: '"hosts: files dns": source order for name lookups.' },
        { path: '/etc/hosts', purpose: 'Static name → address entries, consulted first.' },
        { path: '/etc/resolv.conf', purpose: 'nameserver (up to 3), search domains, options timeout/attempts/ndots/rotate.' },
        { path: '/proc/sys/net/ipv4/tcp_syn_retries', purpose: 'SYN retransmissions before connect() gives up (default 6 ≈ 127 s).' },
        { path: '/proc/sys/net/ipv4/ip_local_port_range', purpose: 'Ephemeral source ports (default 32768 60999).' },
        { path: 'Service configs (sshd ListenAddress, nginx listen, …)', purpose: 'Which address/port each program binds.' },
      ],
    },
  ],

  directives: [
    { name: 'listen / ListenAddress / bind', compiledDefault: 'usually 0.0.0.0 and ::', recommended: 'Only the addresses clients use', explanation: 'The address a service binds. 0.0.0.0 = every IPv4 address; 127.0.0.1 = loopback only.', security: 'Binding to loopback hides a service from the network (useful behind a local proxy); binding everywhere exposes it on every interface.' },
    { name: 'nameserver', compiledDefault: '127.0.0.1 if none', recommended: 'Two or more reachable servers', explanation: 'DNS servers asked in order (max 3).', security: 'Clients trust these answers; use servers you control.' },
    { name: 'search', compiledDefault: 'local domain', recommended: 'Your internal domain(s)', explanation: 'Suffixes tried for short names.', security: 'Long search lists multiply queries and can resolve a typo to an unexpected host.' },
    { name: 'options ndots:N', compiledDefault: '1', recommended: '1 (5 in Kubernetes pods)', explanation: 'Names with fewer dots than N try search domains first.', security: 'High ndots sends external names through every search domain first (slow, leaks names to internal DNS).' },
    { name: 'options timeout:N attempts:N', compiledDefault: '5 / 2', recommended: '1–2 / 2', explanation: 'Per-query wait and number of rounds over all servers.', security: 'Shorter timeouts make dead servers less painful.' },
    { name: 'hosts: files dns (nsswitch.conf)', compiledDefault: 'files dns', recommended: 'files dns (plus sss/ldap if used)', explanation: 'Order of lookup sources.', security: 'Static /etc/hosts entries silently override DNS.' },
    { name: 'net.ipv4.tcp_syn_retries', compiledDefault: '6', recommended: 'default', explanation: 'How long connect() keeps retrying an unanswered SYN.', security: 'Lowering it shortens hangs but can break slow links.' },
  ],

  troubleshootingIntro: `
### Name first, then transport, then application
1. **Which address is used?** \`getent hosts NAME\` (what the app sees) vs \`dig NAME\` (what DNS says). Disagreement → /etc/hosts or search list. Nothing → resolv.conf / DNS server.
2. **Does the transport connect?** \`nc -zv -w 5 HOST PORT\`. Succeeded → the problem is in the application protocol. Refused → nothing listening on that address (or a reset by a firewall). Timed out → dropped somewhere.
3. **Is the service bound where you think?** \`ss -tlnp\` on the server: address AND port.
4. **What is on the wire?** \`tcpdump -n port PORT\` on either end; look for SYN without SYN-ACK, RST, ICMP.
`,

  errorMap: [
    { message: 'Name or service not known', layer: 'DNS', meaning: 'NXDOMAIN for every candidate name (and no /etc/hosts entry).', firstCheck: 'dig NAME; check the spelling and search domains' },
    { message: 'Temporary failure in name resolution', layer: 'DNS', meaning: 'No usable answer: DNS server unreachable, timing out or answering SERVFAIL.', firstCheck: 'cat /etc/resolv.conf; dig NAME (status / communication errors); dig @OTHER-SERVER NAME' },
    { message: 'Connection refused', layer: 'Transport', meaning: 'RST: no socket on that address:port (or bound only to 127.0.0.1), or a reject rule.', firstCheck: 'ss -tlnp on the server' },
    { message: 'Connection timed out', layer: 'Transport / network', meaning: 'No reply to repeated SYNs.', firstCheck: 'tcpdump on both ends; firewalls; return route' },
    { message: 'Works by IP, fails by name', layer: 'DNS', meaning: 'The transport is fine; resolution is wrong or failing.', firstCheck: 'getent hosts NAME vs dig NAME' },
    { message: 'Works on the server (localhost), refused remotely', layer: 'Socket binding', meaning: 'Service bound to 127.0.0.1 only.', firstCheck: 'ss -tlnp: Local Address column' },
  ],

  scenarioIds: ['net-dns-resolvconf', 'net-hosts-override', 'net-nginx-loopback', 'ssh-dns-zone-error', 'ssh-config-typo', 'fw-no-established'],
  assessmentId: 'transport',
  references: [
    { title: 'RFC 9293: Transmission Control Protocol', url: 'https://www.rfc-editor.org/rfc/rfc9293' },
    { title: 'RFC 768: User Datagram Protocol', url: 'https://www.rfc-editor.org/rfc/rfc768' },
    { title: 'RFC 6298: Computing TCP\'s Retransmission Timer', url: 'https://www.rfc-editor.org/rfc/rfc6298' },
    { title: 'RFC 1034 / 1035: Domain Names', url: 'https://www.rfc-editor.org/rfc/rfc1035' },
    { title: 'RFC 6335: Service Name and Port Number procedures (IANA registry)', url: 'https://www.rfc-editor.org/rfc/rfc6335' },
    { title: 'resolv.conf(5) and nsswitch.conf(5)', url: 'https://man7.org/linux/man-pages/man5/resolv.conf.5.html' },
    { title: 'tcp(7): Linux TCP parameters', url: 'https://man7.org/linux/man-pages/man7/tcp.7.html' },
  ],
};
