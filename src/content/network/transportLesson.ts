import type { Lesson } from '../types';

export const TRANSPORT_LESSON: Lesson = {
  id: 'transport',
  moduleId: 'A',
  title: 'TCP, UDP and DNS',
  level: 'beginner',
  summary: 'Ports and sockets, the TCP connection lifecycle (handshake, sequence numbers, retransmission, teardown), UDP, and how a name becomes an address.',
  concepts: ['tcp.handshake', 'svc.listening', 'dns.resolution', 'dns.zone', 'net.icmp'],

  what: `
The [IP networking lesson](#/lesson/ipnet/what) showed how a packet finds its way to the right **computer**. But a server runs many programs at once: an SSH server, a web server, perhaps a DNS server. Something has to deliver the data to the right **program** on that computer. That is the job of the **transport layer**, with its two protocols, **TCP** and **UDP**.

People also do not type IP addresses; they type names like srv01.corp.lab. **DNS** (the Domain Name System) turns those names into the addresses IP needs. This lesson covers both, because almost every "cannot connect" problem is either a name that does not resolve or a connection that does not get through, and you need to tell the two apart quickly.

### Ports and sockets
A **port** is a number from 0 to 65535 that identifies one program's "door" on a computer. Some numbers are conventions everyone uses: 22 for SSH, 53 for DNS, 80 and 443 for web (HTTP and HTTPS), 3389 for Remote Desktop.

A server program **listens** on a port: it asks the operating system to hand it any connection that arrives for that port. The combination of protocol, IP address and port is called a **socket**. For example, the SSH server (sshd) listens on the socket TCP 0.0.0.0:22. The address 0.0.0.0 means "every address this computer has".

The client needs a port too, so the replies can find their way back to it. Its kernel picks a temporary one, called an **ephemeral port** (on Linux, a number between 32768 and 60999). One connection is then identified by five values, the **5-tuple**: protocol, source IP, source port, destination IP and destination port. Because each client uses a different source port, thousands of clients can talk to the same server port at the same time without mixing up their data.

### TCP and UDP
The two transport protocols make very different promises:

| | TCP | UDP |
|---|---|---|
| Starting a conversation | a 3-way handshake first; an explicit close at the end | none: just send |
| Reliability | numbers every byte, confirms receipt, resends what was lost | none: the application must cope with loss |
| Order and flow control | delivers bytes in order; the receiver's window limits the pace | no ordering, no flow control |
| Typical uses | SSH, HTTP, SMB, LDAP, RDP | DNS queries, NTP, DHCP, syslog, voice |
| If nothing listens on the port | the server answers with a reset (RST): "Connection refused" | ICMP port unreachable (or no answer at all) |

Think of TCP as a phone call: you dial, the other side picks up, you talk, and you notice when the line drops. UDP is more like a postcard: quick and cheap, but nobody tells you if it got lost.

### DNS in a nutshell
When a program needs an address for a name, it calls a standard library function, \`getaddrinfo()\`. That function, called the **stub resolver**, first checks the local file \`/etc/hosts\`. If the name is not there, it asks the DNS servers listed in \`/etc/resolv.conf\`, usually over UDP port 53 (TCP for large answers). For short names like "srv01" it also tries adding the **search domains** from that file, so "srv01" becomes "srv01.corp.lab".

> What the simulator models: the TCP handshake, resets, SYN retransmission with growing waits, data segments with sequence and acknowledgement numbers, and the FIN close; UDP; ICMP port unreachable; and a glibc-style resolver talking to a BIND-style DNS server. It does not model TCP congestion control or window behaviour.
`,

  internals: `
### How a TCP connection starts: the 3-way handshake
Before any data flows, client and server agree to talk. This takes three packets, and each packet carries **flags** that say what kind of packet it is.

1. **SYN** ("synchronise"): the client picks a random starting number for its bytes, the **Initial Sequence Number (ISN)**, and sends it along with some options (the largest segment it can receive (MSS), selective acknowledgements (SACK), window scaling, timestamps). The client's socket is now in the state SYN_SENT.
2. **SYN-ACK**: if a program is listening on that address and port, the server's kernel answers with its own ISN and acknowledges the client's (ack = client ISN + 1). The server socket is in SYN_RECV. Note that the server **program** is not involved yet: the kernel does this on its own.
3. **ACK**: the client acknowledges the server's number (ack = server ISN + 1). Both sides are now ESTABLISHED. The new connection waits in the listening socket's **accept queue** until the program picks it up with accept().

Two things can go wrong here, and they look different:
- **Nothing is listening** on that port: the server's kernel answers the SYN with a reset (**RST, ACK**). The client fails at once with **ECONNREFUSED: "Connection refused"**.
- **Nothing answers at all** (a firewall drops the packet, or there is no route back): Linux resends the SYN after 1, 2, 4, 8, 16 and 32 seconds (\`net.ipv4.tcp_syn_retries = 6\`) and gives up after about 127 seconds with **ETIMEDOUT: "Connection timed out"**. Where does 127 come from? The wait doubles after every attempt, starting at 1 second: 1 + 2 + 4 + 8 + 16 + 32 seconds between the seven SYNs, plus a last 64-second wait for an answer to the final one: 1 + 2 + 4 + 8 + 16 + 32 + 64 = 127. With a different \`tcp_syn_retries\`, add up the doubling waits in the same way (one wait per retry, plus the final one). Most programs give up sooner with their own timeout (\`ssh -o ConnectTimeout\`, \`curl -m\`, \`nc -w\`).

So "refused" means a computer answered and said no; "timed out" means nobody answered at all. That difference tells you where to look.

### Sequence numbers and acknowledgements
TCP numbers every byte it sends. A segment that carries *n* bytes starting at sequence number *s* is confirmed by an acknowledgement *s + n*, which means "I have received everything before this byte". The SYN and FIN flags each count as one byte. If an acknowledgement does not arrive in time, the sender assumes the data was lost and sends it again. The receiver also advertises a **window**: how much unacknowledged data it is willing to accept at once. This is **flow control**, and it stops a fast sender from overwhelming a slow receiver.

tcpdump and Wireshark normally show **relative** sequence numbers (counting from 0) because the real ones are large random numbers.

### How a TCP connection ends
Each side closes its own direction by sending **FIN** ("finished"). The usual pattern is FIN, ACK (often combined with the other side's FIN), ACK. The side that closed first then waits in **TIME_WAIT** for twice the maximum segment lifetime (2 × MSL), so that late packets from the old connection cannot be confused with a new one using the same ports.

**RST** (reset) ends a connection immediately, without the polite exchange. You see it when nothing listens, when a program crashes, or when a firewall rejects a connection "with tcp reset".

### UDP
UDP simply sends a datagram and forgets about it. Its header is only 8 bytes (source port, destination port, length, checksum). There is no handshake and no resending. If reliability matters, the application handles it: a DNS resolver, for example, asks again after a timeout (set with \`options timeout:N attempts:N\` in resolv.conf). A datagram sent to a port where nothing listens normally triggers an **ICMP port unreachable** message, which lets the resolver move on to the next server straight away.

### Name resolution step by step (glibc on Linux)
1. **Where to look.** \`/etc/nsswitch.conf\` has a line \`hosts: files dns\`: check **/etc/hosts** first. If the name is found there, that answer wins and DNS is never asked.
2. **Which names to try.** If the name has fewer dots than the \`ndots\` option (default 1), the resolver first tries it with each **search** domain added (\`srv01\` becomes \`srv01.corp.lab.\`); otherwise it tries the name exactly as typed first.
3. **Ask the servers.** For each candidate name, it asks each **nameserver** in resolv.conf in order, up to \`attempts\` times, waiting \`timeout\` seconds for each answer.
4. **Interpret the answer**, as described next.

What the resolver does with each answer:
- **NOERROR with an answer**: done, the address is returned.
- **NXDOMAIN** ("this name does not exist"): try the next candidate name.
- **Timeouts, SERVFAIL or an unreachable server**: stop. The program gets EAI_AGAIN, shown as "Temporary failure in name resolution".
- **Every candidate answered NXDOMAIN**: the program gets "Name or service not known".

### The DNS server side
A DNS server is **authoritative** for the zones it holds: it is the official source for those names, and it marks its answers with the *aa* flag. In the lab, ns1 is authoritative for \`corp.lab\`, loaded from a zone file. A zone file contains an **SOA** record (the zone's serial number and timers), **NS** records (which servers serve the zone) and the actual data, such as **A** records (name to IPv4 address) and **CNAME** records (an alias for another name).

- If the zone file has an error and does not load, the server answers **SERVFAIL** ("I should know, but something is broken").
- A server that is not authoritative for the name and does not look it up elsewhere for you answers **REFUSED**.
- A **CNAME** answer is followed to the final A record: \`www.corp.lab → srv01.corp.lab → 10.0.20.10\`.

### Different tools look in different places
- \`dig\` asks a DNS server directly. It ignores /etc/hosts and does not use the search list unless you add \`+search\`.
- \`getent hosts\` uses exactly the same path as ssh, curl and ping (nsswitch, /etc/hosts, then DNS with the search list).
- \`nslookup\` uses the search list but ignores /etc/hosts.

When these tools disagree, the disagreement itself is the clue: for example, \`getent\` and \`dig\` giving different addresses points straight at /etc/hosts. The resolver tracer below runs the simulator's resolver step by step so you can watch this happen.
`,

  deployment: [
    {
      id: 'sockets',
      platform: 'Linux: sockets and TCP',
      summary: 'Start a throw-away TCP service, look at listening sockets and connections, and capture a complete TCP conversation. Best done with two real VMs (or two terminals); the steps marked as simulated also work in the sandbox.',
      prerequisites: ['Two Linux machines (or two terminals), with netcat-openbsd and tcpdump installed.'],
      steps: [
        { title: 'Start a listener', command: 'nc -l -k 0.0.0.0 9000', what: 'netcat (`nc`) opens a listening TCP socket on port 9000 on every address (0.0.0.0) and prints whatever clients send. `-k` keeps it listening after a client disconnects.', why: 'This gives you a tiny server whose behaviour you fully control, so you can watch a socket being bound, a connection being accepted and then closed.', expected: '(waits for connections)' },
        { title: 'Inspect listening sockets', command: 'sudo ss -tlnp', what: '`ss` lists sockets: `-t` TCP only, `-l` listening sockets, `-n` show numbers instead of names, `-p` show the owning process (needs root).', why: 'The Local Address column shows where the program listens. 0.0.0.0 means every address; 127.0.0.1 means only this machine can connect. If there is no line for a port, clients get "Connection refused".', expected: 'LISTEN 0 1 0.0.0.0:9000 0.0.0.0:* users:(("nc",pid=2210,fd=3))', simulated: true },
        { title: 'Capture while connecting', command: 'sudo tcpdump -i eth0 -n "tcp port 9000"\n# from the other host:\nprintf hello | nc -q1 server 9000', what: 'tcpdump prints every packet to or from port 9000. From the other host, netcat connects, sends "hello" and closes. In the capture, `[S]` is the SYN, `[S.]` the SYN-ACK, `[.]` an ACK, `[P.]` data being pushed, and `[F.]` a FIN.', why: 'Seeing the handshake, your own data and the close on the wire turns the theory above into something you can recognise in any capture.', expected: 'IP 10.0.10.25.51514 > 10.0.20.10.9000: Flags [S], seq 1520034, ... length 0\nIP 10.0.20.10.9000 > 10.0.10.25.51514: Flags [S.], seq 99102, ack 1520035, ... length 0\nIP 10.0.10.25.51514 > 10.0.20.10.9000: Flags [.], ack 1, ... length 0\nIP 10.0.10.25.51514 > 10.0.20.10.9000: Flags [P.], seq 1:6, ack 1, ... length 5\nIP 10.0.10.25.51514 > 10.0.20.10.9000: Flags [F.], seq 6, ack 1, ... length 0' },
        { title: 'Connection refused vs timed out', command: 'nc -zv -w 5 server 9001     # nothing listening\nnc -zv -w 5 server 3306     # dropped by a firewall', what: '`-z` only tests whether a connection can be made, `-v` prints the result, `-w 5` gives up after 5 seconds. The two ports fail in two different ways.', why: '"Refused" means a reset came back: the server is reachable but nothing listens on that port. "Timed out" means nothing came back at all: look for a firewall or a routing problem instead.', expected: 'nc: connect to server port 9001 (tcp) failed: Connection refused\nnc: connect to server port 3306 (tcp) failed: Connection timed out' },
        { title: 'See established connections', command: 'ss -tn state established', what: 'Lists the TCP connections that are currently open, with the address and port at each end.', why: 'Each line is one 5-tuple. This shows who is connected to a service right now, for example which clients have SSH sessions open.', expected: 'Recv-Q Send-Q Local Address:Port Peer Address:Port\n0      0      10.0.20.10:22      10.0.10.25:51514', simulated: true },
      ],
    },
    {
      id: 'resolver',
      platform: 'Linux: resolver configuration',
      summary: 'Check and set how a Debian host turns names into addresses. On Ubuntu, a local service called systemd-resolved manages /etc/resolv.conf for you; use `resolvectl` there instead of editing the file.',
      prerequisites: ['A Debian 12 VM.'],
      steps: [
        { title: 'Read the resolver configuration', command: 'cat /etc/nsswitch.conf | grep hosts\ncat /etc/resolv.conf\ncat /etc/hosts', what: 'Shows the order of lookup sources (nsswitch.conf), the DNS servers, search domains and options (resolv.conf), and the static name entries (/etc/hosts).', why: 'These three small files completely decide what `getaddrinfo()` does, so they are the first place to look when names behave strangely.', expected: 'hosts:          files dns\nsearch corp.lab\nnameserver 10.0.10.53', simulated: true },
        { title: 'Resolve like an application', command: 'getent hosts srv01\ngetent hosts srv01.corp.lab', what: 'Looks the names up through NSS, exactly like a program would: /etc/hosts first, then DNS with the search list.', why: 'This is the answer ssh, curl and ping will get, so test with this rather than with dig when you want to know what an application sees.', expected: '10.0.20.10      srv01.corp.lab', simulated: true },
        { title: 'Ask DNS directly', command: 'dig srv01.corp.lab\ndig @10.0.10.53 srv01.corp.lab +short\ndig www.corp.lab', what: 'dig sends a question straight to a DNS server and prints the full answer: the status (NOERROR, NXDOMAIN, SERVFAIL), the flags (aa = authoritative), the server that answered and any CNAME chain. `@10.0.10.53` picks the server; `+short` prints only the result.', why: 'Comparing dig with getent separates "the DNS server gives a wrong answer" from "this host does something else", such as an /etc/hosts entry.', expected: ';; ->>HEADER<<- opcode: QUERY, status: NOERROR\nwww.corp.lab.  3600 IN CNAME srv01.corp.lab.\nsrv01.corp.lab. 3600 IN A 10.0.20.10', simulated: true },
        { title: 'Tune timeouts', command: 'sudo nano /etc/resolv.conf\n\nsearch corp.lab\nnameserver 10.0.10.53\nnameserver 10.0.10.54\noptions timeout:2 attempts:2 rotate', what: 'Lists two DNS servers, waits 2 seconds per try, goes round the servers twice, and with `rotate` spreads the first query over both servers.', why: 'With the defaults (5 seconds, 2 attempts), a dead first server makes every single lookup wait 10 seconds, which feels like the whole system is slow.', expected: '' },
      ],
    },
    {
      id: 'windows-dns',
      platform: 'Windows',
      summary: 'The same client-side checks on Windows, with PowerShell.',
      prerequisites: ['Windows 10/11 or Windows Server, with PowerShell.'],
      steps: [
        { title: 'Resolve like an application', command: 'Resolve-DnsName srv01.corp.lab\nResolve-DnsName srv01.corp.lab -DnsOnly -Server 10.0.10.53', what: 'The first command uses the Windows DNS client the way applications do: hosts file, cache, then DNS with the suffix search list. `-DnsOnly -Server` skips the hosts file and cache and asks one server directly.', why: 'It is the same distinction as getent versus dig on Linux: what applications see versus what the DNS server says.', expected: 'Name             Type TTL  Section IPAddress\nsrv01.corp.lab   A    3600 Answer  10.0.20.10' },
        { title: 'Cache and sockets', command: 'Get-DnsClientCache | Select-Object -First 5\nipconfig /flushdns\nGet-NetTCPConnection -State Listen', what: 'Shows a few entries from the DNS client cache, clears the cache, and lists the TCP ports this computer listens on.', why: 'Windows remembers both answers and "name does not exist" results for a while. After a DNS fix, an old cache entry can keep the problem alive until it expires or you flush it.', expected: 'Successfully flushed the DNS Resolver Cache.' },
      ],
    },
  ],

  configIntro: `
Most transport-layer settings belong to the applications themselves: each program decides which address and port it listens on. A few kernel parameters control timing and port ranges. Name resolution on Linux is controlled by three small files.

The resolver tracer below runs the simulator's resolver against the lab, so you can see each step for any name you type.
`,

  configFiles: [
    {
      platform: 'Linux',
      items: [
        { path: '/etc/nsswitch.conf', purpose: '"hosts: files dns": the order in which sources are asked for names.' },
        { path: '/etc/hosts', purpose: 'Fixed name-to-address entries, checked before DNS.' },
        { path: '/etc/resolv.conf', purpose: 'nameserver (up to 3), search domains, and options such as timeout, attempts, ndots and rotate.' },
        { path: '/proc/sys/net/ipv4/tcp_syn_retries', purpose: 'How many times an unanswered SYN is resent before connect() gives up (default 6, about 127 s).' },
        { path: '/proc/sys/net/ipv4/ip_local_port_range', purpose: 'The range of ephemeral source ports (default 32768 60999).' },
        { path: 'Service configs (sshd ListenAddress, nginx listen, …)', purpose: 'Which address and port each program listens on.' },
      ],
    },
  ],

  directives: [
    { name: 'listen / ListenAddress / bind', compiledDefault: 'usually 0.0.0.0 and ::', recommended: 'Only the addresses clients use', explanation: 'The address a service listens on. 0.0.0.0 means every IPv4 address of the machine; 127.0.0.1 means loopback only, which only the machine itself can reach.', security: 'Listening on loopback hides a service from the network, which is useful when a local proxy sits in front of it. Listening everywhere exposes it on every interface.' },
    { name: 'nameserver', compiledDefault: '127.0.0.1 if none', recommended: 'Two or more reachable servers', explanation: 'The DNS servers to ask, in order (at most 3).', security: 'Clients believe whatever these servers answer, so use servers you control.' },
    { name: 'search', compiledDefault: 'local domain', recommended: 'Your internal domain(s)', explanation: 'Domain suffixes the resolver adds to short names ("srv01" becomes "srv01.corp.lab").', security: 'A long search list multiplies the number of queries and can turn a typo into an unexpected host.' },
    { name: 'options ndots:N', compiledDefault: '1', recommended: '1 (5 in Kubernetes pods)', explanation: 'Names with fewer dots than N are tried with the search domains first.', security: 'A high ndots sends external names through every search domain first: slower, and it leaks the names you look up to your internal DNS.' },
    { name: 'options timeout:N attempts:N', compiledDefault: '5 / 2', recommended: '1–2 / 2', explanation: 'How long to wait for each answer, and how many rounds to make over all servers.', security: 'Shorter timeouts make a dead DNS server less painful.' },
    { name: 'hosts: files dns (nsswitch.conf)', compiledDefault: 'files dns', recommended: 'files dns (plus sss/ldap if used)', explanation: 'The order of name lookup sources.', security: 'An entry in /etc/hosts silently overrides DNS, which makes forgotten entries a common cause of "wrong server" problems.' },
    { name: 'net.ipv4.tcp_syn_retries', compiledDefault: '6', recommended: 'default', explanation: 'How long connect() keeps resending an unanswered SYN.', security: 'Lowering it makes failures appear sooner, but can break connections over slow links.' },
  ],

  troubleshootingIntro: `
### Check the name first, then the connection, then the application
When a program cannot connect to a server by name, three different things could be wrong, and each is checked differently. Work through them in this order, because each step depends on the one before.

1. **Which address does the name give?** Run \`getent hosts NAME\` (what applications see) and \`dig NAME\` (what DNS says). If they disagree, look at /etc/hosts and the search list. If neither gives an address, look at /etc/resolv.conf and the DNS server.
2. **Can a TCP connection be made?** Run \`nc -zv -w 5 HOST PORT\`. If it succeeds, the network path and the listener are fine, and the problem is inside the application (wrong password, wrong URL, and so on). "Connection refused" means nothing listens on that address and port (or a firewall rejected the connection with a reset). "Timed out" means the packets are dropped somewhere along the way.
3. **Is the service listening where you think it is?** Run \`ss -tlnp\` on the server and check both the address and the port. A service listening on 127.0.0.1 can only be reached from the server itself.
4. **What actually travels on the wire?** Run \`tcpdump -n port PORT\` on the client and on the server. Look for a SYN with no SYN-ACK (dropped), an RST (refused), or ICMP error messages.

### Scoring engines: web and DNS checks
In competitions such as CCDC, a **scoring engine** tests your services automatically, and many monitoring tools work the same way. Most are written in the Go language. Their **web check** makes **one GET request**, does not follow redirects, usually ignores certificate problems, then compares the status code and looks for a specific word on the page. Their **DNS check** sends **one UDP query** straight to your DNS server and compares the address in the answer.

The status wording varies between engines, but the **Error** line is Go's own error text, and it tells you which layer failed:

| Engine error | Layer | What it tells you | First check |
|---|---|---|---|
| \`Get "http://…": dial tcp IP:80: connect: connection refused\` | Transport | The server answered with a reset: nothing listens on port 80 (nginx stopped or failed to start, or listens elsewhere) | \`systemctl status nginx\`, \`nginx -t\`, \`ss -tlnp\` |
| "check timed out" (web or DNS) | Network / firewall | No answer at all: a firewall drop rule, no route back, or the host is down. For DNS: is **UDP** port 53 allowed, not just TCP? | \`nft list ruleset\`, \`ip route\`, \`dig @SERVER NAME\` |
| \`dial tcp: lookup NAME on NS:53: no such host\` / \`server misbehaving\` | DNS | The engine could not turn the name into an address (NXDOMAIN or SERVFAIL). The web server was never contacted | \`dig NAME\` (look at status:) |
| \`expected status code 200, got 403\` | Application | nginx answered but refused: usually file permissions, since nginx's worker processes run as www-data | \`tail /var/log/nginx/error.log\`, \`namei -l FILE\` |
| \`expected status code 200, got 301\` / \`404\` | Application | A redirect the engine does not follow, or a missing page | \`curl -i URL\` (without -L) |
| \`expected content "…" not found in the page\` | Content | 200 OK but the wrong page: defaced, the default page, or the wrong server block answered | \`curl URL\`, \`ls -l\` the web root, compare with a backup |
| DNS: \`expected 10.0.20.10, got …\` | DNS data | The server answered with the wrong record | the zone file, \`dig @SERVER NAME\` |
| DNS: \`server answered SERVFAIL\` | DNS server | The zone did not load: a single bad line makes the server reject the whole file | \`journalctl -u named\`, \`named-checkzone\` |
| DNS: \`read udp …->IP:53: read: connection refused\` | DNS server | ICMP port unreachable came back: nothing listens on UDP 53 there (named is stopped) | \`systemctl status named\`, \`ss -ulnp\` |

A check that gets **200 with the wrong content** fails just as surely as one that times out. So test with the same request the engine makes (\`curl -sS -i URL\`, \`dig @SERVER NAME\`), not just "is the service running?". You can practise all of these in the **Scored services** tickets.
`,

  errorMap: [
    { message: 'Name or service not known', layer: 'DNS', meaning: 'Every name the resolver tried came back NXDOMAIN ("does not exist"), and /etc/hosts has no entry either.', firstCheck: 'dig NAME; check the spelling and the search domains' },
    { message: 'Temporary failure in name resolution', layer: 'DNS', meaning: 'No usable answer at all: the DNS server is unreachable, does not answer in time, or answers SERVFAIL.', firstCheck: 'cat /etc/resolv.conf; dig NAME (look at status and communication errors); dig @OTHER-SERVER NAME' },
    { message: 'Connection refused', layer: 'Transport', meaning: 'A reset (RST) came back: no program listens on that address and port (or it listens only on 127.0.0.1), or a firewall rule rejects the connection.', firstCheck: 'ss -tlnp on the server' },
    { message: 'Connection timed out', layer: 'Transport / network', meaning: 'The SYN was sent several times and nothing ever came back.', firstCheck: 'tcpdump on both ends; firewalls; the return route' },
    { message: 'Works by IP, fails by name', layer: 'DNS', meaning: 'The connection itself is fine; turning the name into an address fails or gives the wrong address.', firstCheck: 'getent hosts NAME vs dig NAME' },
    { message: 'lookup NAME on IP:53: server misbehaving', layer: 'DNS', meaning: 'This is how Go programs (scoring engines and many tools) report a SERVFAIL or REFUSED answer: the DNS server answered but could not resolve the name.', firstCheck: 'dig @IP NAME (status:); journalctl -u named on the server' },
    { message: 'Works on the server (localhost), refused remotely', layer: 'Socket binding', meaning: 'The service listens on 127.0.0.1 only, so only the server itself can reach it.', firstCheck: 'ss -tlnp: the Local Address column' },
  ],

  scenarioIds: ['net-dns-resolvconf', 'net-hosts-override', 'net-nginx-loopback', 'ssh-dns-zone-error', 'ssh-config-typo', 'fw-no-established', 'score-web-forbidden', 'score-web-defaced', 'score-dns-hijack', 'score-dns-servfail', 'score-dns-firewall'],
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
