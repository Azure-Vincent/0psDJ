import type { Assessment } from '../types';

export const IP_ASSESSMENT: Assessment = {
  id: 'ipnet',
  title: 'IP networking knowledge check',
  questions: [
    {
      id: 'ip-q-broadcast', kind: 'text', level: 'beginner',
      prompt: 'What is the broadcast address of 172.16.5.130/26?',
      accept: ['172.16.5.191'], placeholder: 'a.b.c.d', concepts: ['net.cidr'],
      explanation: '/26 = blocks of 64: .128–.191. Network 172.16.5.128, broadcast 172.16.5.191, hosts .129–.190.',
    },
    {
      id: 'ip-q-hosts', kind: 'text', level: 'beginner',
      prompt: 'How many usable host addresses does a /27 network have?',
      accept: ['30'], placeholder: 'number', concepts: ['net.cidr'],
      explanation: '2^(32−27) = 32 addresses, minus the network and broadcast addresses = 30.',
    },
    {
      id: 'ip-q-lpm', kind: 'single', level: 'intermediate',
      prompt: 'A host has these routes. Which next hop does it use for **10.0.20.77**?',
      exhibit: 'default via 10.0.10.1 dev eth0\n10.0.0.0/16 via 10.0.10.2 dev eth0\n10.0.20.0/24 via 10.0.10.3 dev eth0\n10.0.10.0/24 dev eth0 proto kernel scope link src 10.0.10.25',
      options: [
        { text: '10.0.10.1 (the default route)', misconception: 'The default route (/0) only applies when nothing more specific matches.' },
        { text: '10.0.10.2 (the /16)', misconception: 'The /16 matches, but a /24 also matches and is more specific.' },
        { text: '10.0.10.3 (the /24)', correct: true },
        { text: 'Directly on eth0 (connected route)', misconception: '10.0.20.77 is not inside the connected 10.0.10.0/24.' },
      ],
      concepts: ['net.routing'],
      explanation: 'Longest prefix match: of all routes containing the destination, the one with the largest prefix length wins, regardless of order.',
    },
    {
      id: 'ip-q-arp-mac', kind: 'single', level: 'beginner',
      prompt: 'ws01 (10.0.10.25/24, gateway 10.0.10.1) sends a packet to 10.0.20.10. Whose MAC address is the **destination MAC** of the frame leaving ws01?',
      options: [
        { text: 'The MAC of 10.0.20.10', misconception: 'ARP only works on the local segment; ws01 cannot learn (and does not need) the MAC of a host behind a router.' },
        { text: 'The MAC of the gateway 10.0.10.1', correct: true },
        { text: 'ff:ff:ff:ff:ff:ff (broadcast)', misconception: 'Broadcast is used for the ARP request, not for the data frame.' },
      ],
      concepts: ['net.arp', 'net.routing'],
      explanation: 'The IP destination stays 10.0.20.10 end to end; the Ethernet destination is always the next hop on the current segment. The router builds a new frame on the next segment.',
    },
    {
      id: 'ip-q-order', kind: 'order', level: 'intermediate',
      prompt: 'Order what happens when ws01 pings 10.0.20.10 for the first time (cold ARP caches).',
      items: [
        'ws01 looks up its routing table: default via 10.0.10.1',
        'ws01 broadcasts an ARP request for 10.0.10.1',
        'rtr01 replies with its eth0 MAC address',
        'ws01 sends the echo request in a frame addressed to rtr01',
        'rtr01 decrements the TTL and looks up 10.0.20.10: connected on eth1',
        'rtr01 ARPs for 10.0.20.10 on eth1',
        'rtr01 forwards the packet in a new frame to srv01',
        'srv01 replies, routing the reply via its own default gateway 10.0.20.1',
      ],
      concepts: ['net.arp', 'net.routing'],
      explanation: 'Each hop: route lookup → ARP for the next hop if needed → new frame. The reply is routed independently by srv01.',
    },
    {
      id: 'ip-q-own-unreachable', kind: 'single', level: 'intermediate',
      prompt: 'ping prints **From 10.0.10.25 icmp_seq=1 Destination Host Unreachable** on host 10.0.10.25. What does that tell you?',
      options: [
        { text: 'The router 10.0.10.1 could not reach the destination', misconception: 'Then the message would say "From 10.0.10.1". The source shown is the host that generated the error.' },
        { text: 'This host failed to resolve the MAC of its next hop (ARP failed): check the gateway, the prefix, or whether an on-link target is up', correct: true },
        { text: 'The destination firewall rejected the ping', misconception: 'A reject would come from the destination\'s address, and with a different ICMP code.' },
      ],
      concepts: ['net.arp', 'net.icmp'],
      explanation: 'The local kernel generates this error when neighbour resolution fails. Look at ip route get DEST and ip neigh.',
    },
    {
      id: 'ip-q-forward', kind: 'multi', level: 'intermediate',
      prompt: 'A Linux router has net.ipv4.ip_forward=0. Which statements are true? (Select all that apply.)',
      options: [
        { text: 'Clients can still ping the router\'s own addresses', correct: true },
        { text: 'Packets addressed to other networks are answered with ICMP host unreachable', correct: true },
        { text: 'Traffic between two hosts on the same LAN behind the router is affected', misconception: 'On-link traffic never goes through the router.' },
        { text: 'Setting it with sysctl -w survives a reboot', misconception: 'sysctl -w changes the running kernel only; persist it in /etc/sysctl.conf or /etc/sysctl.d/.' },
      ],
      concepts: ['net.routing', 'net.icmp'],
      explanation: 'Forwarding is a per-kernel switch; the router remains a normal host for its own addresses.',
    },
    {
      id: 'ip-q-return', kind: 'single', level: 'advanced',
      prompt: 'tcpdump on a server shows ICMP echo requests arriving from 10.0.10.25 but no echo replies leaving. The server firewall accepts ICMP. What is the most likely cause?',
      options: [
        { text: 'The client has the wrong gateway', misconception: 'The requests DO arrive, so the client\'s path works.' },
        { text: 'The server has no route back to 10.0.10.0/24 (e.g. missing default gateway)', correct: true },
        { text: 'ARP failure on the client\'s LAN', misconception: 'Again, the packets reached the server: the forward path is fine.' },
      ],
      concepts: ['net.routing'],
      explanation: 'Replies are routed by the server\'s own table. Check ip route get 10.0.10.25 on the server.',
    },
    {
      id: 'ip-q-cmd', kind: 'text', level: 'beginner',
      prompt: 'Type the command that shows which route, next hop and source address Linux would use to reach 10.0.20.10.',
      accept: [/^(sudo\s+)?ip\s+(-4\s+)?r(oute)?\s+get\s+10\.0\.20\.10$/], placeholder: 'command', concepts: ['net.routing'],
      explanation: 'ip route get 10.0.20.10 performs the real lookup, including policy routing and the chosen source address.',
    },
    {
      id: 'ip-q-mask', kind: 'single', level: 'advanced',
      prompt: 'A host is configured as 10.0.10.25/16 while the LAN is really 10.0.10.0/24 and the router is 10.0.10.1. What happens when it connects to 10.0.20.10?',
      options: [
        { text: 'It works: the default gateway is still configured', misconception: 'The connected /16 route is more specific than the default route and contains 10.0.20.10, so the gateway is never used.' },
        { text: 'The host ARPs for 10.0.20.10 on its LAN, gets no answer, and reports "No route to host"', correct: true },
        { text: 'The router rejects the traffic', misconception: 'The packet never reaches the router.' },
      ],
      concepts: ['net.cidr', 'net.routing', 'net.arp'],
      explanation: 'A too-short prefix makes remote addresses look on-link.',
    },
  ],
};

export const TRANSPORT_ASSESSMENT: Assessment = {
  id: 'transport',
  title: 'TCP, UDP and DNS knowledge check',
  questions: [
    {
      id: 'tr-q-handshake', kind: 'order', level: 'beginner',
      prompt: 'Order the TCP segments of a short HTTP exchange where the client closes first.',
      items: ['SYN (client)', 'SYN, ACK (server)', 'ACK (client)', 'PSH, ACK: HTTP request (client)', 'PSH, ACK: HTTP response (server)', 'FIN, ACK (client)', 'FIN, ACK (server)', 'ACK (client)'],
      concepts: ['tcp.handshake'],
      explanation: 'Three-way handshake, data in both directions (each segment acknowledging the other side), then FIN from each side and a final ACK.',
    },
    {
      id: 'tr-q-ack', kind: 'text', level: 'intermediate',
      prompt: 'A client sends a segment with seq = 1001 carrying 200 bytes of data. What acknowledgement number does the server send if it received everything?',
      accept: ['1201'], placeholder: 'number', concepts: ['tcp.handshake'],
      explanation: 'ack = next expected byte = 1001 + 200 = 1201.',
    },
    {
      id: 'tr-q-refused', kind: 'single', level: 'beginner',
      prompt: 'Who sends the RST that makes a client print "Connection refused" when nothing listens on the port?',
      options: [
        { text: 'The server\'s kernel', correct: true },
        { text: 'The server application', misconception: 'No application owns the port: that is the problem. The TCP stack answers on its own.' },
        { text: 'The client\'s kernel', misconception: 'The client receives the RST; it does not invent it (though it would for a local destination).' },
      ],
      concepts: ['tcp.handshake', 'svc.listening'],
      explanation: 'The RST proves the packet reached a live host. That rules out routing and silent firewalls on the path.',
    },
    {
      id: 'tr-q-timeout', kind: 'text', level: 'intermediate',
      prompt: 'With Linux defaults (tcp_syn_retries = 6, initial RTO 1 s), after roughly how many **seconds** does an unanswered connect() give up?',
      accept: ['127', '~127', '127s', '127 s'], placeholder: 'seconds', concepts: ['tcp.handshake'],
      explanation: '1 + 2 + 4 + 8 + 16 + 32 + 64 = 127 seconds.',
    },
    {
      id: 'tr-q-loopback', kind: 'single', level: 'intermediate',
      prompt: 'ss on a server shows: `LISTEN 0 511 127.0.0.1:80 0.0.0.0:* users:(("nginx",...))`. What happens to a connection from 10.0.10.25 to 10.0.20.10:80?',
      options: [
        { text: 'It is accepted: nginx listens on port 80', misconception: 'A socket matches an address AND a port; 127.0.0.1:80 does not match 10.0.20.10:80.' },
        { text: 'The server answers RST: Connection refused', correct: true },
        { text: 'It times out', misconception: 'The kernel actively refuses; nothing is silently dropped (unless a firewall does so first).' },
      ],
      concepts: ['svc.listening'],
      explanation: 'Bind to 0.0.0.0 (or the specific external address) to accept remote connections.',
    },
    {
      id: 'tr-q-udp', kind: 'multi', level: 'intermediate',
      prompt: 'Which are properties of UDP? (Select all that apply.)',
      options: [
        { text: 'No handshake before data', correct: true },
        { text: 'The application must handle loss (e.g. resolver retries)', correct: true },
        { text: 'A datagram to a closed port usually triggers ICMP port unreachable', correct: true },
        { text: 'Sequence numbers guarantee ordering', misconception: 'That is TCP. UDP has ports, length and checksum only.' },
      ],
      concepts: ['net.icmp', 'dns.resolution'],
      explanation: 'DNS uses UDP for speed; the resolver\'s timeout/attempts provide reliability.',
    },
    {
      id: 'tr-q-resolve-order', kind: 'order', level: 'intermediate',
      prompt: 'Order what glibc does for `ssh srv01` on a host with "hosts: files dns" and "search corp.lab".',
      items: ['Look for "srv01" in /etc/hosts', 'Query the first nameserver for srv01.corp.lab.', 'On NXDOMAIN, query for srv01.', 'On NXDOMAIN again, fail: Name or service not known'],
      concepts: ['dns.resolution'],
      explanation: 'Files first; a short name (fewer dots than ndots=1) tries search domains before the bare name.',
    },
    {
      id: 'tr-q-dig-getent', kind: 'single', level: 'intermediate',
      prompt: '`dig +short srv01.corp.lab` prints 10.0.20.10, but `getent hosts srv01.corp.lab` prints 10.0.20.99. Where does 10.0.20.99 come from?',
      options: [
        { text: 'A stale DNS cache on the DNS server', misconception: 'dig asked the DNS server and got .10. The difference is on the client.' },
        { text: '/etc/hosts (or another NSS source before DNS)', correct: true },
        { text: 'The search domain', misconception: 'Both commands looked up the same fully qualified name.' },
      ],
      concepts: ['dns.resolution'],
      explanation: 'dig bypasses NSS; getent uses it like applications do.',
    },
    {
      id: 'tr-q-servfail', kind: 'single', level: 'advanced',
      prompt: 'Every name in corp.lab fails with "Temporary failure in name resolution"; `dig @10.0.10.53 srv01.corp.lab` shows status: SERVFAIL. Where do you look first?',
      options: [
        { text: 'The client\'s /etc/resolv.conf', misconception: 'The client reached the server and got an answer (SERVFAIL). Its configuration works.' },
        { text: 'The DNS server\'s log: the zone probably failed to load', correct: true },
        { text: 'The firewall on the DNS server', misconception: 'A blocked query would time out, not produce SERVFAIL.' },
      ],
      concepts: ['dns.zone'],
      explanation: 'An authoritative server that cannot load its zone answers SERVFAIL; journalctl -u named and named-checkzone show why.',
    },
    {
      id: 'tr-q-port', kind: 'text', level: 'beginner',
      prompt: 'On which UDP/TCP port does DNS listen?',
      accept: ['53'], placeholder: 'port', concepts: ['dns.resolution'],
      explanation: 'Port 53, UDP for most queries and TCP for large responses and zone transfers.',
    },
  ],
};
