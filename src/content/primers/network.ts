// Primers for the networking lessons: plain-language explanations, each idea
// with a concrete example from the lab. Example output is taken from the
// simulator (ws01 = 10.0.10.25, rtr01 = the router, srv01 = 10.0.20.10,
// ns1 = 10.0.10.53, ext01 = 203.0.113.80 on the "Internet").

import type { Primer } from '../types';

export const IPNET_PRIMER: Primer = {
  oneLiner: 'Every machine on a network has an **IP address**; to reach another machine it either talks to it directly (same network) or hands the packet to a **router** (the gateway), which forwards it closer to the destination.',
  analogy: `
Think of a building with numbered flats and a post room. A letter to someone on **your own floor** you just carry over yourself. A letter to **another building** you drop at the post room (the **default gateway**), which knows where other buildings are.

The **street address** is the IP address (10.0.10.25). The **name on the letterbox** is the MAC address (52:54:00:d4:00:19): you need it for the last few metres, to put the letter in the right box. **ARP** is asking out loud on the landing "who lives at flat 10.0.10.1?" and writing down the letterbox name.

Where the analogy stops: real routers forward packets in microseconds, keep no copy, and each packet of a conversation may be handled independently.`,
  ideas: [
    {
      title: 'An address has a network part and a host part',
      explain: 'The **prefix length** (the /24 in 10.0.10.25/24) says how many leading bits name the network. /24 means the first three numbers are the network (10.0.10) and the last number is the host. Two machines with the same network part are on the **same subnet** and can talk directly.',
      example: 'ws01 is **10.0.10.25/24** and ns1 is **10.0.10.53/24**: both in 10.0.10.0/24, so ws01 talks to ns1 directly. srv01 is **10.0.20.10**: network 10.0.20 is different, so ws01 needs a router to reach it.',
    },
    {
      title: 'The routing table decides where each packet goes',
      explain: 'For every packet the kernel looks up the destination in its **routing table** and picks the most specific matching route (the longest prefix). A **default route** (0.0.0.0/0) matches everything else and points at the gateway.',
      example: 'On ws01, `ip route` shows two routes. 10.0.10.53 matches `10.0.10.0/24 dev eth0`: deliver directly. 10.0.20.10 only matches `default via 10.0.10.1`: send it to rtr01.\n```\ndefault via 10.0.10.1 dev eth0 onlink\n10.0.10.0/24 dev eth0 proto kernel scope link src 10.0.10.25\n```',
    },
    {
      title: 'ARP turns the next hop\'s IP address into a MAC address',
      explain: 'Ethernet frames are delivered by **MAC address**, not IP address. Before sending, the host needs the MAC of the **next hop**: the destination itself on the same subnet, otherwise the gateway. It asks with an ARP broadcast and caches the answer (`ip neigh`).',
      example: 'When ws01 sends to srv01 (10.0.20.10), it never ARPs for 10.0.20.10: that address is not on its subnet. It ARPs for the **gateway** 10.0.10.1 and puts rtr01\'s MAC on the frame:\n```\n10.0.10.1 dev eth0 lladdr 52:54:00:a1:00:01 REACHABLE\n```',
    },
    {
      title: 'Routers forward, and replies need a route back',
      explain: 'A router has an address in each network it connects, forwards packets between them, and decreases the **TTL** by one at each hop. Communication needs a path **in both directions**: the server must be able to route its reply back to the client.',
      example: 'rtr01 has 10.0.10.1 (office) and 10.0.20.1 (servers). A ping from ws01 to srv01 arrives with TTL 63 instead of 64: one router was crossed. If srv01 had no default route, the request would arrive but the reply would never leave srv01.',
    },
    {
      title: 'ICMP reports what went wrong',
      explain: '`ping` uses ICMP echo request/reply. Routers also send ICMP **errors** back to the sender: "destination unreachable", "TTL exceeded". The error message tells you how far the packet got.',
      example: '"Destination Host Unreachable" from 10.0.10.1 means the packet reached rtr01, but rtr01 could not find srv01 on its local network (ARP failed). A plain timeout with no message means something dropped the packet silently, often a firewall.',
    },
  ],
  walkthrough: {
    title: 'ws01 pings srv01 (10.0.10.25 → 10.0.20.10)',
    intro: 'Follow one packet from alice\'s workstation to the server on another subnet and back.',
    steps: [
      { label: 'Is the destination on my subnet?', detail: 'ws01 compares 10.0.20.10 with its own network 10.0.10.0/24. Different network: the packet must go to the gateway. `ip route get 10.0.20.10` shows the decision.', show: '10.0.20.10 via 10.0.10.1 dev eth0 src 10.0.10.25 uid 1000' },
      { label: 'Find the gateway\'s MAC address', detail: 'ws01 looks up 10.0.10.1 in its neighbour cache. If it is missing, it broadcasts an ARP request "who has 10.0.10.1?" and rtr01 answers with 52:54:00:a1:00:01.' },
      { label: 'Send the frame to the router', detail: 'The Ethernet frame goes to **rtr01\'s MAC**, but the IP packet inside still says destination **10.0.20.10**. MAC addresses change at every hop; IP addresses do not (unless NAT is involved).' },
      { label: 'rtr01 forwards', detail: 'rtr01 receives the packet on eth0, looks up 10.0.20.10 in its own routing table (connected route 10.0.20.0/24 on eth1), lowers the TTL from 64 to 63, ARPs for srv01 and sends a new frame out of eth1.' },
      { label: 'srv01 replies', detail: 'srv01 answers to 10.0.10.25. That is not on its subnet, so it uses **its** default route (10.0.20.1) and the reply travels the same way back.' },
      { label: 'ws01 sees the reply', detail: 'ping prints one line per reply. ttl=63 confirms one router in the path.', show: '64 bytes from 10.0.20.10: icmp_seq=1 ttl=63 time=1.350 ms' },
    ],
  },
  misconceptions: [
    { myth: 'If I can ping the gateway, the network is fine.', truth: 'That only proves your own subnet works. The next router, the destination\'s subnet, its default route and any firewall in between are all still untested. Test hop by hop: gateway, then the destination, then by name.' },
    { myth: 'The router changes the destination IP address at each hop.', truth: 'Only the **MAC addresses** change at each hop. Source and destination IP addresses stay the same end to end (NAT is the exception, and it is done deliberately).' },
    { myth: 'A wrong subnet mask only affects that one host.', truth: 'It changes which addresses the host thinks are local. With /16 instead of /24, ws01 would ARP for 10.0.20.10 directly instead of using the gateway, and nothing would answer.' },
  ],
  checks: [
    { q: 'ws01 (10.0.10.25/24) sends to ns1 (10.0.10.53). Which MAC address is on the frame?', a: 'ns1\'s own MAC: the destination is on the same subnet, so no router is involved.' },
    { q: 'ws01 sends to 203.0.113.80. Which MAC address is on the frame?', a: 'rtr01\'s (10.0.10.1\'s) MAC: the destination is not local, so the next hop is the default gateway.' },
    { q: 'A ping reply shows ttl=62. What does it tell you, if the server started at 64?', a: 'Two routers decreased the TTL on the way back: the reply crossed two hops.' },
    { q: 'srv01 has no default route. ws01 pings it. What happens?', a: 'The request reaches srv01, but srv01 has no route back to 10.0.10.25, so it cannot send the reply. ws01 sees a timeout.' },
  ],
};

export const TRANSPORT_PRIMER: Primer = {
  oneLiner: 'IP gets packets to the right machine; **TCP** and **UDP** get them to the right **program** on that machine using **port numbers**, and **DNS** turns names like srv01.corp.lab into the addresses IP needs.',
  analogy: `
An IP address is the address of an office building; the **port** is the department (22 = the SSH desk, 80 = the web desk, 53 = the DNS desk).

**TCP** is a phone call: you dial, the other side picks up (the handshake), you talk in order, and you notice when the line drops. **UDP** is a postcard: you send it and hope; no call set-up, no confirmation.

**DNS** is the company directory: you look up "srv01.corp.lab" and get its number, 10.0.20.10. If the directory is wrong, you dial the wrong number even though the phone network works perfectly.`,
  ideas: [
    {
      title: 'A connection is identified by addresses and ports',
      explain: 'A server program **listens** on a port. A client picks a temporary (ephemeral) source port. The four values (client IP:port, server IP:port) identify one conversation, so many clients can talk to the same port at once.',
      example: 'On srv01, `ss -tlnp` lists who listens where:\n```\nLISTEN 0 128  0.0.0.0:22  0.0.0.0:*  users:(("sshd",pid=414,fd=3))\nLISTEN 0 511  0.0.0.0:80  0.0.0.0:*  users:(("nginx",pid=421,fd=6))\n```\nalice\'s SSH session is 10.0.10.25:53567 → 10.0.20.10:22.',
    },
    {
      title: 'TCP opens with a three-way handshake',
      explain: 'The client sends **SYN**, the server answers **SYN-ACK**, the client confirms with **ACK**. Only then is data exchanged. How the handshake fails tells you a lot.',
      example: '`nc -zv srv01.corp.lab 22` succeeds: the handshake completed. Port 25 has nothing listening and a firewall drops the SYN, so ws01 waits and reports "Connection timed out". If nothing listened and no firewall interfered, srv01 would answer with a **RST**: "Connection refused".',
    },
    {
      title: '"Refused" and "timed out" mean different things',
      explain: '**Refused** = the machine answered "nobody here" (RST): the network path works, the service is not listening. **Timed out** = no answer at all: a firewall drop, a routing problem or a machine that is down.',
      example: 'nginx stopped on srv01 → `curl http://srv01.corp.lab/` says "Connection refused" immediately. nftables dropping port 80 → curl hangs and then says "Connection timed out".',
    },
    {
      title: 'UDP has no connection',
      explain: 'UDP sends single datagrams with no handshake and no retransmission. The application retries if it cares. DNS queries, DHCP and NTP use UDP because each exchange is one short question and one short answer.',
      example: 'A DNS query from ws01 to ns1 is one UDP packet to port 53 and one reply. If it is lost, the resolver simply asks again after its timeout (`options timeout:2 attempts:2` in /etc/resolv.conf).',
    },
    {
      title: 'DNS: names, records and the resolver',
      explain: 'Programs ask the system **resolver**, which reads `/etc/resolv.conf` and queries the listed name server. The server answers from its **zone** (A records for IPv4 addresses, AAAA for IPv6, SRV for services). Answers are cached for their TTL.',
      example: '```\n$ cat /etc/resolv.conf\nsearch corp.lab\nnameserver 10.0.10.53\n$ dig +short srv01.corp.lab\n10.0.20.10\n```\nBecause of `search corp.lab`, typing `ssh srv01` works too: the resolver tries srv01.corp.lab.',
    },
  ],
  walkthrough: {
    title: 'alice runs "curl http://srv01.corp.lab/"',
    steps: [
      { label: 'Resolve the name', detail: 'curl asks the resolver for srv01.corp.lab. ws01 sends a UDP query to ns1 (10.0.10.53:53) and gets an A record.', show: ';; ANSWER SECTION:\nsrv01.corp.lab.\t\t3600\tIN\tA\t10.0.20.10' },
      { label: 'Pick a source port', detail: 'The kernel chooses an unused ephemeral port on ws01, for example 52088. The connection will be 10.0.10.25:52088 → 10.0.20.10:80.' },
      { label: 'Handshake', detail: 'SYN goes out (through rtr01, see the IP lesson), srv01 answers SYN-ACK because nginx listens on port 80, ws01 sends ACK. The connection is ESTABLISHED.' },
      { label: 'Request and response', detail: 'curl sends "GET / HTTP/1.1" with "Host: srv01.corp.lab". nginx answers with a status line and the page. TCP numbers the bytes and retransmits anything lost.', show: 'HTTP/1.1 200 OK\nServer: nginx/1.22.1\nContent-Type: text/html' },
      { label: 'Close', detail: 'Both sides send FIN and acknowledge. The client side stays in TIME_WAIT for a while so late packets of this connection are not confused with a new one.' },
    ],
  },
  misconceptions: [
    { myth: '"Connection refused" means the firewall blocked me.', truth: 'Usually the opposite: the packet reached the machine and its kernel answered RST because no program listens on that port (or a firewall rule explicitly **rejects**). A firewall that **drops** produces a timeout.' },
    { myth: 'If ping works, the service must be reachable.', truth: 'Ping tests ICMP to the machine, not TCP to the port. The service may be stopped, listening only on 127.0.0.1, or blocked by a rule that allows ICMP.' },
    { myth: 'I changed the DNS record, so everybody sees the new address now.', truth: 'Resolvers and clients cache answers for the record\'s TTL (3600 s here). Old answers can live for up to an hour after the change.' },
  ],
  checks: [
    { q: 'ss shows nginx on 127.0.0.1:80 only. What do clients on other machines get?', a: '"Connection refused": the kernel has no listener on the external address, so it answers RST.' },
    { q: 'Which protocol and port does a normal DNS query use?', a: 'UDP port 53 (TCP 53 for large answers and zone transfers).' },
    { q: 'ssh to srv01 hangs for 10 seconds, then "Connection timed out". Name two possible causes.', a: 'A firewall dropping TCP 22 (on srv01 or a router), a routing problem (no path or no route back), or srv01 being down.' },
    { q: '`ssh srv01` works but `ssh srv01.corp.lab.` was never typed. Why does the short name work?', a: 'The `search corp.lab` line in /etc/resolv.conf: the resolver appends the domain to short names.' },
  ],
};

export const DHCP_PRIMER: Primer = {
  oneLiner: '**DHCP** hands out IP addresses automatically: a new machine shouts "I need an address", a DHCP server offers one from its pool together with the gateway and DNS server, and the machine **leases** it for a limited time.',
  analogy: `
A hotel reception desk. A guest arrives and asks for a room (DISCOVER). The desk offers room 100 (OFFER). The guest says "yes, room 100 please" (REQUEST) and gets the key card with the Wi-Fi password and the breakfast hours written on it (ACK: address, gateway, DNS).

The key card stops working at checkout time (lease expiry). A guest who wants to stay asks for an extension well before that (renewal at half the lease time).

Where the analogy stops: the "guest" has no address yet when asking, so everything is shouted to the whole floor (broadcast).`,
  ideas: [
    {
      title: 'Four messages: DISCOVER, OFFER, REQUEST, ACK',
      explain: 'The client broadcasts **DISCOVER**. Servers answer with an **OFFER**. The client broadcasts a **REQUEST** naming the offer it accepts (so other servers withdraw theirs), and the chosen server confirms with an **ACK**. Remember it as **DORA**.',
      example: 'On ws02, `sudo dhclient -v eth0` when it already has a lease skips straight to REQUEST/ACK:\n```\nDHCPREQUEST for 10.0.10.100 on eth0 to 255.255.255.255 port 67\nDHCPACK of 10.0.10.100 from 10.0.10.53\nbound to 10.0.10.100 -- renewal in 300 seconds.\n```',
    },
    {
      title: 'The lease carries more than an address',
      explain: 'Options in the ACK configure the client: **router** (default gateway), **domain-name-servers**, domain name, lease time. A wrong option breaks every client at once while the address itself looks fine.',
      example: 'ns1\'s /etc/dhcp/dhcpd.conf for the office:\n```\noption domain-name-servers 10.0.10.53;\ndefault-lease-time 600;\n\nsubnet 10.0.10.0 netmask 255.255.255.0 {\n    range 10.0.10.100 10.0.10.150;\n    option routers 10.0.10.1;\n}\n```\nA typo in `option routers` gives every laptop an address but no way off its subnet.',
    },
    {
      title: 'Leases expire and are renewed',
      explain: 'At **T1** (half the lease) the client asks its server directly to renew. If that fails, at **T2** (7/8 of the lease) it asks any server by broadcast. At expiry it must stop using the address.',
      example: 'With a 600 s lease, ws02 renews after 300 s ("renewal in 300 seconds"). If ns1 is down for an hour, ws02 keeps working until the lease runs out, then loses its address: DHCP outages show up late.',
    },
    {
      title: 'Broadcasts stop at routers: relays forward them',
      explain: 'DISCOVER is a broadcast and routers do not forward broadcasts. A **DHCP relay** on the router catches it, writes its own address on that network into the **giaddr** field, and forwards it as unicast to the server. The server picks the pool whose subnet contains giaddr.',
      example: 'dev01 on VLAN 30 has no DHCP server on its subnet. rtr01 runs dhcrelay on eth3.30 (10.0.30.1) and forwards to ns1. ns1 sees giaddr 10.0.30.1 and leases from its 10.0.30.0/24 pool.',
    },
  ],
  walkthrough: {
    title: 'ws02, a laptop, joins the office network',
    steps: [
      { label: 'DISCOVER', detail: 'ws02 has no address. It sends a broadcast from 0.0.0.0:68 to 255.255.255.255:67 with its MAC address in the message.' },
      { label: 'OFFER', detail: 'ns1\'s dhcpd picks a free address from the office pool (10.0.10.100) and offers it, with the options.' },
      { label: 'REQUEST', detail: 'ws02 broadcasts "I take 10.0.10.100 from server 10.0.10.53". Broadcasting lets any other DHCP server know its offer was declined.' },
      { label: 'ACK', detail: 'ns1 records the lease in /var/lib/dhcp/dhcpd.leases and confirms. ws02 configures 10.0.10.100/24, default route via 10.0.10.1 and nameserver 10.0.10.53.' },
      { label: 'Renew', detail: 'After half the lease time ws02 sends a unicast REQUEST to ns1, gets a new ACK and the timer starts again. Nothing visible happens for the user.' },
    ],
  },
  misconceptions: [
    { myth: 'A client with an IP address got it from DHCP correctly, so DHCP is fine.', truth: 'It may have a valid address but wrong **options** (gateway, DNS), or an old lease that has not expired yet while the server is already broken.' },
    { myth: 'One DHCP server per subnet is required.', truth: 'One central server can serve many subnets through **relays** on the routers; the giaddr field tells it which subnet each request comes from.' },
    { myth: 'An address starting with 169.254 is a configuration I set somewhere.', truth: 'That is the automatic link-local fallback a client uses when **no DHCP answer arrived at all**: look at the path to the server.' },
  ],
  checks: [
    { q: 'What do the four letters of DORA stand for?', a: 'DISCOVER, OFFER, REQUEST, ACK.' },
    { q: 'Every laptop gets an address but cannot reach anything outside its subnet. Which DHCP setting do you check first?', a: '`option routers` (the default gateway) in the server\'s subnet declaration.' },
    { q: 'Why does a DHCP server on another subnet need a relay?', a: 'Clients broadcast and routers do not forward broadcasts. The relay forwards the request as unicast and fills in giaddr.' },
    { q: 'The DHCP server crashed 10 minutes ago and nobody complains yet. Why?', a: 'Clients keep their leases until they expire; problems appear when leases cannot be renewed.' },
  ],
};

export const NAT_PRIMER: Primer = {
  oneLiner: '**NAT** lets many machines with private addresses share one public address: the router rewrites the source address of outgoing packets (and remembers it so replies find their way back), and can forward incoming connections to an inside server (**port forwarding**).',
  analogy: `
A company switchboard. Employees have internal extensions (private addresses). When someone calls out, the other side sees the company's main number (the public address). The switchboard remembers which extension made the call and puts the reply through to it.

**Port forwarding** is the receptionist rule "calls for sales on line 80 go to extension 10.0.20.10".

Where the analogy stops: NAT does not decide *whether* a call is allowed. That is the firewall's job.`,
  ideas: [
    {
      title: 'Private addresses are not routed on the Internet',
      explain: '10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16 can be used by anyone inside a network, so Internet routers will not deliver packets **to** them. A packet leaving with source 10.0.10.25 could never get a reply.',
      example: 'ext01 (203.0.113.80) stands for a server on the Internet: it has no route to 10.0.0.0/8. Without NAT on rtr01, a reply from ext01 to 10.0.10.25 has nowhere to go.',
    },
    {
      title: 'Source NAT (masquerade) rewrites outgoing connections',
      explain: 'For connections leaving through the uplink, the router replaces the private source address with its own public address. **Masquerade** is source NAT that uses whatever address the outgoing interface has.',
      example: 'rtr01\'s ruleset:\n```\nchain postrouting {\n  type nat hook postrouting priority srcnat; policy accept;\n  oifname "eth2" masquerade\n}\n```\nws01\'s request to ext01 leaves rtr01 with source 203.0.113.2.',
    },
    {
      title: 'The router remembers each translation',
      explain: 'Connection tracking (**conntrack**) keeps a table of translated flows, so replies are rewritten back automatically. Only the first packet of a connection consults the NAT rules.',
      example: '`conntrack -L` on rtr01 shows both directions. The reply is expected at 203.0.113.2, the router, not at ws01:\n```\ntcp 6 117 ... src=10.0.10.25 dst=203.0.113.80 sport=47002 dport=80 src=203.0.113.80 dst=203.0.113.2 sport=80 dport=47002\n```',
    },
    {
      title: 'Destination NAT (port forwarding) publishes an inside server',
      explain: 'For incoming connections to the public address on a given port, the router rewrites the **destination** to an inside server. The firewall then sees the **inside** address, because DNAT happens before filtering.',
      example: '`iifname "eth2" tcp dport 80 dnat to 10.0.20.10:80`: a browser on ext01 opening http://203.0.113.2/ actually gets srv01\'s page. A forward rule that allows it must mention 10.0.20.10 port 80, not 203.0.113.2.',
    },
  ],
  walkthrough: {
    title: 'ws01 downloads a page from ext01 through rtr01',
    steps: [
      { label: 'ws01 sends the SYN', detail: '10.0.10.25:47002 → 203.0.113.80:80. ws01 has no idea NAT exists.' },
      { label: 'rtr01 routes it to eth2', detail: 'Routing chooses the uplink eth2 (default route). The forward filter allows office → Internet.' },
      { label: 'Postrouting: masquerade', detail: 'The packet leaves eth2 rewritten as 203.0.113.2:47002 → 203.0.113.80:80, and conntrack stores the mapping.' },
      { label: 'ext01 replies to the router', detail: 'ext01 sees a client at 203.0.113.2 and sends its SYN-ACK there.' },
      { label: 'rtr01 reverses the translation', detail: 'conntrack recognises the reply, rewrites the destination back to 10.0.10.25:47002 and forwards it to ws01. curl gets "HTTP/1.1 200 OK".' },
    ],
  },
  misconceptions: [
    { myth: 'NAT protects my network like a firewall.', truth: 'NAT hides addresses as a side effect. What is allowed through is decided by filter rules; a router with NAT and no filter still forwards anything routed to it.' },
    { myth: 'A forward rule for a port forward should match the public address and port.', truth: 'DNAT runs in prerouting, before the forward filter. The filter sees the translated inside address and port.' },
    { myth: 'Changing a NAT rule fixes existing connections.', truth: 'NAT decisions are stored per connection. Existing flows keep the old translation until they end or are flushed (`conntrack -F`).' },
  ],
  checks: [
    { q: 'Which part of the packet does masquerade change, and in which chain?', a: 'The source address (and possibly port), in the postrouting chain, after routing.' },
    { q: 'Outbound connections from the office time out; capturing on eth2 shows source 10.0.10.25. What is missing?', a: 'The source NAT (masquerade) rule for traffic leaving eth2.' },
    { q: 'Port 8080 on the public address is forwarded to 10.0.20.10:80. Which port must the forward filter allow?', a: 'Port 80 to 10.0.20.10: the filter sees the packet after DNAT.' },
    { q: 'Why can\'t ext01 open a connection to 10.0.10.25 directly?', a: 'Private addresses are not routed on the Internet: ext01 has no route to 10.0.0.0/8, and nothing on rtr01 forwards it in.' },
  ],
};

export const VLAN_PRIMER: Primer = {
  oneLiner: 'A **VLAN** splits one physical switch into several separate networks: ports are assigned to VLAN 10, 20 or 30, machines in different VLANs cannot talk directly, and a **router** connects the VLANs where traffic should cross.',
  analogy: `
One large open-plan office with coloured carpets. Blue (VLAN 10) people only hear blue people; green (VLAN 20) only green. The colours share the same floor (the same switch), but conversations stay within a colour.

A **trunk** is a corridor that carries all colours at once: every person walking through wears a colour badge (the **802.1Q tag**) so the other end knows where they belong.

The **router** is the reception desk where a blue person can leave a message for a green person, if the rules allow it.`,
  ideas: [
    {
      title: 'Access ports belong to one VLAN',
      explain: 'A port connected to a normal computer is an **access port**: frames arrive untagged, the switch assigns them to the port\'s VLAN (its **PVID**) and only delivers them to ports in the same VLAN. The computer does not know VLANs exist.',
      example: 'On sw01, `bridge vlan show` lists swp1–swp4 in VLAN 10 (office), swp5–swp6 in VLAN 20 (servers), swp8–swp9 in VLAN 30 (dev):\n```\nswp1   10 PVID Egress Untagged\nswp5   20 PVID Egress Untagged\nswp8   30 PVID Egress Untagged\n```',
    },
    {
      title: 'Trunks carry several VLANs with tags',
      explain: 'A link that must carry more than one VLAN (switch to router, switch to switch, switch to hypervisor) is a **trunk**. Each frame gets a 4-byte **802.1Q tag** with the VLAN number.',
      example: 'swp7 is the trunk to rtr01. It carries VLAN 30 tagged: `swp7  1 PVID Egress Untagged / 30`. rtr01 sees VLAN 30 as the interface **eth3.30**.',
    },
    {
      title: 'Each VLAN is its own subnet and broadcast domain',
      explain: 'Broadcasts (ARP, DHCP DISCOVER) stay inside the VLAN. Each VLAN therefore gets its own IP subnet, and traffic between VLANs must be **routed**.',
      example: 'dev01 (10.0.30.25, VLAN 30) cannot ARP for srv01 (VLAN 20) even though both cables end on sw01. It sends to its gateway 10.0.30.1 on rtr01, which routes to 10.0.20.10.',
    },
    {
      title: 'Router-on-a-stick: one cable, many gateways',
      explain: 'A router with one trunk link can have a **sub-interface** per VLAN (eth3.30 with VLAN ID 30), each with the gateway address of that VLAN. The VLAN ID on the router must match the switch.',
      example: 'If rtr01\'s sub-interface were created as eth3.31 by mistake, dev01\'s frames (tagged 30) would arrive on rtr01 but match no interface: the gateway would be unreachable for the whole VLAN.',
    },
  ],
  walkthrough: {
    title: 'dev01 (VLAN 30) opens a web page on srv01 (VLAN 20)',
    steps: [
      { label: 'dev01 sends to its gateway', detail: '10.0.20.10 is not in 10.0.30.0/24, so dev01 sends an untagged frame to the MAC of 10.0.30.1 out of its only interface.' },
      { label: 'sw01 classifies the frame', detail: 'The frame enters access port swp8: PVID 30, so it belongs to VLAN 30.' },
      { label: 'Out on the trunk, tagged', detail: 'The gateway\'s MAC was learned on swp7 in VLAN 30. sw01 sends the frame there with an 802.1Q tag "VLAN 30".' },
      { label: 'rtr01 routes between VLANs', detail: 'The tag delivers the frame to eth3.30. rtr01 routes it to eth1 (10.0.20.0/24) and the packet reaches srv01 through access port swp5 in VLAN 20.' },
      { label: 'The reply takes the same path in reverse', detail: 'srv01 → 10.0.20.1 → rtr01 → eth3.30 (tagged 30) → sw01 swp7 → swp8 untagged → dev01.' },
    ],
  },
  misconceptions: [
    { myth: 'Machines on the same switch can always talk to each other.', truth: 'Only within the same VLAN. Different VLANs are separate networks even on the same switch.' },
    { myth: 'VLANs are a security boundary on their own.', truth: 'They separate broadcast domains. Whatever the router between them allows can still cross; the firewall rules on the router decide.' },
    { myth: 'The computer needs to be configured for its VLAN.', truth: 'On an access port the switch does it; the computer sends untagged frames. Only trunk endpoints (routers, hypervisors) configure tags.' },
  ],
  checks: [
    { q: 'A new server is plugged into swp9 but should be on the server network. What do you change?', a: 'swp9\'s access VLAN (PVID) on sw01 from 30 to 20.' },
    { q: 'What does an 802.1Q tag contain that matters most here?', a: 'The VLAN ID (12 bits).' },
    { q: 'All of VLAN 30 cannot reach its gateway after a trunk change. What do you check on sw01?', a: 'That VLAN 30 is still allowed on the trunk port swp7 (`bridge vlan show dev swp7`).' },
    { q: 'Why does each VLAN need its own IP subnet?', a: 'Hosts decide "local or via gateway" by subnet. A VLAN is a separate broadcast domain, so cross-VLAN traffic must go through the router.' },
  ],
};

export const IPV6_PRIMER: Primer = {
  oneLiner: '**IPv6** is the newer IP version with 128-bit addresses, so plenty for every device: hosts usually configure themselves from **router advertisements** (SLAAC), find neighbours with **Neighbor Discovery** instead of ARP, and run side by side with IPv4 (dual stack).',
  analogy: `
IPv4 is a city where street numbers ran out, so whole buildings share one number (NAT). IPv6 is a city with numbers for every room, generous enough that each street (subnet, /64) has more numbers than will ever be used.

New residents do not ask a desk for a number: the street sign (the router advertisement) says "this street is 2001:db8:30::/64", and each resident builds their own number from the street name plus something unique of their own.`,
  ideas: [
    {
      title: 'Reading an IPv6 address',
      explain: 'Eight groups of four hex digits. Leading zeros in a group can be dropped, and one run of all-zero groups can be written as `::`. Subnets are almost always **/64**: the first half is the network, the second half the host (the **interface identifier**).',
      example: 'dev01\'s address `2001:db8:30:0:5054:ff:fee7:1e/64`: network 2001:db8:30::/64 (VLAN 30), interface identifier 5054:ff:fee7:1e derived from its MAC 52:54:00:e7:00:1e.',
    },
    {
      title: 'Every interface has a link-local address',
      explain: 'Addresses starting with **fe80::** exist on every IPv6 interface and only work on that link. Routers use them as the next hop, and Neighbor Discovery runs over them.',
      example: 'dev01\'s default route points at a link-local address, not a global one:\n```\ndefault via fe80::5054:ff:fea1:4 dev eth0 proto ra metric 1024\n```',
    },
    {
      title: 'SLAAC: hosts configure themselves from router advertisements',
      explain: 'Routers periodically send **Router Advertisements** (RA) with the prefix and flags. A host builds its address from the prefix plus its interface identifier, and installs a default route to the router. The **M** and **O** flags say whether to use DHCPv6 for addresses or other settings.',
      example: 'rtr01 runs radvd on eth3.30 announcing 2001:db8:30::/64. dev01 shows `proto ra` on its routes: they came from the advertisement, not from a config file.',
    },
    {
      title: 'Neighbor Discovery replaces ARP, and needs ICMPv6',
      explain: 'Instead of ARP broadcasts, IPv6 uses ICMPv6 **Neighbor Solicitation/Advertisement** sent to multicast addresses. A firewall that blocks all ICMPv6 breaks IPv6 completely.',
      example: 'srv01\'s ruleset has `meta l4proto ipv6-icmp accept`. Remove it and srv01 stops answering neighbour solicitations: nothing reaches it over IPv6, while IPv4 keeps working.',
    },
  ],
  walkthrough: {
    title: 'dev01 gets IPv6 connectivity without any configuration',
    steps: [
      { label: 'Link-local address', detail: 'When eth0 comes up, dev01 forms fe80::5054:ff:fee7:1e from its MAC and checks nobody else uses it (duplicate address detection).' },
      { label: 'Router solicitation', detail: 'dev01 asks "any routers here?" with an ICMPv6 Router Solicitation to the all-routers multicast group.' },
      { label: 'Router advertisement', detail: 'radvd on rtr01 answers with prefix 2001:db8:30::/64, its own link-local address and lifetimes.' },
      { label: 'Global address and default route', detail: 'dev01 combines the prefix with its interface identifier and installs a default route via the router\'s link-local address.', show: 'inet6 2001:db8:30:0:5054:ff:fee7:1e/64 scope global dynamic mngtmpaddr\n   valid_lft 86400sec preferred_lft 14400sec' },
      { label: 'Talk to srv01 over IPv6', detail: 'curl -6 http://srv01.corp.lab/ uses srv01\'s AAAA record (2001:db8:20::10). Before sending, dev01 resolves the router\'s link-layer address with Neighbor Discovery.' },
    ],
  },
  misconceptions: [
    { myth: 'IPv6 needs NAT like IPv4.', truth: 'There are enough addresses for every device. Firewalls control access; NAT is generally not used with IPv6.' },
    { myth: 'Blocking ICMPv6 is safe hardening.', truth: 'Neighbor Discovery and router advertisements are ICMPv6. Blocking it breaks address resolution and path MTU discovery.' },
    { myth: 'If IPv4 works, the IPv6 path does too.', truth: 'They are separate stacks with separate routes, forwarding settings and firewall rules. Dual-stack clients may prefer IPv6 and fail where IPv4 would have worked.' },
  ],
  checks: [
    { q: 'Shorten 2001:0db8:0030:0000:0000:0000:0000:0010.', a: '2001:db8:30::10' },
    { q: 'Which address family and prefix does fe80::1 belong to?', a: 'IPv6 link-local, fe80::/10 (used as fe80::/64): valid only on the attached link.' },
    { q: 'dev01 has only a fe80:: address. What is probably missing?', a: 'Router advertisements: radvd not running on the router, or RAs blocked.' },
    { q: 'What replaces ARP in IPv6?', a: 'Neighbor Discovery: ICMPv6 Neighbor Solicitation and Advertisement messages.' },
  ],
};

export const NETIF_PRIMER: Primer = {
  oneLiner: 'A **network interface** is how the kernel sends and receives frames: physical NICs (eth0), virtual ones (bridges, VLAN sub-interfaces, dummies), each with a name, a MAC address, a state and an MTU, and configuration that must refer to the right name.',
  analogy: `
Interfaces are the doors of a building. Some open to a street (a physical NIC with a cable), some to an internal corridor (a bridge joining several doors), some are signs on a door saying "only visitors with a blue badge" (a VLAN sub-interface).

The configuration file is a list of instructions per door name. Rename a door ("eth0" becomes "ens3") and the instructions point at a door that no longer exists.`,
  ideas: [
    {
      title: 'Names, MAC addresses and state',
      explain: 'Each interface has a **name** (eth0, ens3, br0), a **MAC address**, an administrative state (UP/DOWN) and a carrier state (LOWER_UP = a link is detected).',
      example: '`ip -d link show eth0` on srv01:\n```\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n    link/ether 52:54:00:c3:00:0a brd ff:ff:ff:ff:ff:ff\n```\nUP and LOWER_UP: enabled and cable connected.',
    },
    {
      title: 'Virtual interfaces are built on top of others',
      explain: 'A **bridge** joins interfaces into one switch, a **VLAN sub-interface** (eth3.30) sends and receives frames with one VLAN tag on its parent, a **dummy** interface is an always-up place to put an address.',
      example: 'sw01 is a Linux bridge br0 with ports swp1–swp9. rtr01\'s eth3.30 is VLAN 30 on eth3. `ls /sys/class/net` lists every interface the kernel knows, virtual or not.',
    },
    {
      title: 'Configuration refers to interfaces by name',
      explain: 'On Debian, /etc/network/interfaces has a stanza per interface. If the name in the file does not exist, ifup fails and the machine boots without that address.',
      example: '```\nauto eth0\niface eth0 inet static\n    address 10.0.20.10/24\n    gateway 10.0.20.1\n```\nIf a new virtual NIC appears as ens4, this stanza configures nothing and srv01 is unreachable after reboot.',
    },
    {
      title: 'A bridge port must actually be in the bridge',
      explain: 'A switch port that exists but is not attached to the bridge forwards nothing, even though its link is up.',
      example: 'If swp5 is up but `bridge link` does not list it, srv01 has link light and an address, yet cannot reach its gateway.',
    },
  ],
  walkthrough: {
    title: 'Checking a server\'s network interface from the bottom up',
    steps: [
      { label: 'Does the kernel see the device?', detail: '`ls /sys/class/net` or `ip -br link`. Missing device = driver or virtual hardware problem.', show: 'eth0  lo' },
      { label: 'Is it up, with a link?', detail: '`ip link show eth0`: look for UP and LOWER_UP. UP without LOWER_UP is "no cable/no switch port".' },
      { label: 'Does it have the right address?', detail: '`ip -br addr`: the address should match the plan. No address often means the configuration names another interface.' },
      { label: 'Is the switch side right?', detail: 'On the switch: is the port in the bridge, in the right VLAN (`bridge vlan show`)?' },
      { label: 'Does the gateway answer?', detail: '`ping` the gateway and look at `ip neigh`: a REACHABLE entry means layer 2 works.' },
    ],
  },
  misconceptions: [
    { myth: 'The interface is UP, so the network works.', truth: 'UP is the administrative state. Without LOWER_UP there is no link; with a link, the VLAN, address and bridge membership still matter.' },
    { myth: 'Interface names never change.', truth: 'New virtual hardware, driver changes or predictable naming can change eth0 into ens3. Configuration must follow.' },
    { myth: 'A bridge is something only switches have.', truth: 'Every Linux hypervisor and container host uses bridges to connect virtual machines and containers to the network.' },
  ],
  checks: [
    { q: 'What does LOWER_UP mean in `ip link` output?', a: 'The carrier is detected: there is a working link at the physical layer.' },
    { q: 'After a VM migration, srv01 boots with no address and ifup complains about eth0. First thing to check?', a: 'The interface name: `ip -br link` / `ls /sys/class/net`, and update /etc/network/interfaces.' },
    { q: 'What is eth3.30?', a: 'A VLAN sub-interface on eth3 that sends and receives frames tagged VLAN 30.' },
    { q: 'Which command lists a Linux bridge\'s ports and their VLANs?', a: '`bridge link` and `bridge vlan show`.' },
  ],
};

export const MTU_PRIMER: Primer = {
  oneLiner: 'The **MTU** is the largest packet a link can carry (1500 bytes on Ethernet). Bigger packets must be split or refused, and when a link in the middle is smaller and the "too big" messages are blocked, large transfers hang while small requests still work.',
  analogy: `
Lorries on a road with a low bridge. Most roads allow 4 m high (1500 bytes). One tunnel allows only 3.5 m (a VPN or PPPoE link with MTU 1400).

A tall lorry reaching the tunnel either gets split into two smaller ones (fragmentation) or, if it says "do not split me" (the DF flag), is turned back with a note "max 3.5 m" (ICMP *fragmentation needed*). The sender then loads smaller lorries. If someone tears up the notes (a firewall dropping ICMP), lorries keep arriving and being turned away: the **black hole**.`,
  ideas: [
    {
      title: 'Packet size vs. MTU',
      explain: 'The MTU counts the IP packet: IP header (20 bytes) + transport header + data. A ping with 1472 bytes of data makes a 1500-byte packet (1472 + 8 ICMP + 20 IP).',
      example: 'From ws01:\n```\n$ ping -c 1 -M do -s 1472 10.0.20.10\n1480 bytes from 10.0.20.10: icmp_seq=1 ttl=63\n$ ping -c 1 -M do -s 1473 10.0.20.10\nping: local error: message too long, mtu=1500\n```',
    },
    {
      title: 'Don\'t Fragment and path MTU discovery',
      explain: 'Modern TCP sets **DF** (don\'t fragment). A router that cannot forward a packet that big drops it and sends ICMP "fragmentation needed, next-hop MTU 1400". The sender remembers the smaller **path MTU** and resends.',
      example: '`tracepath -n 203.0.113.80` reports the path MTU it found: `Resume: pmtu 1500 hops 2 back 2`. On a path with a 1400 link it would print pmtu 1400.',
    },
    {
      title: 'TCP MSS: agreeing on segment size up front',
      explain: 'In the handshake each side announces its **MSS** (largest data per segment): MTU minus 40 for IPv4. Routers can clamp the MSS to fit a smaller link, so the problem never happens.',
      example: 'On a 1500 MTU interface the MSS is 1460. A router in front of a 1400-byte tunnel rewrites it to 1360 (`tcp option maxseg size set rt mtu`).',
    },
    {
      title: 'The black hole symptom',
      explain: 'When "fragmentation needed" is filtered, small packets pass and large ones vanish. Typical: the handshake, the login and short commands work; a download, a big page or `ls` of a large directory hangs.',
      example: 'curl from ws01 connects and gets the headers but stalls at "0 out of 4718592 bytes received", while `curl -I` (headers only) works fine.',
    },
  ],
  walkthrough: {
    title: 'A download crosses a link with a smaller MTU',
    steps: [
      { label: 'Handshake', detail: 'Both ends announce MSS 1460 because their own interfaces are 1500. Small packets: everything works.' },
      { label: 'First full-size segment', detail: 'The server sends a 1500-byte packet with DF set.' },
      { label: 'The narrow link', detail: 'The router before the 1400-byte link cannot forward it and may not fragment it (DF). It drops it and sends ICMP type 3 code 4 "fragmentation needed, MTU 1400" to the server.' },
      { label: 'If the ICMP arrives', detail: 'The server lowers its path MTU for this destination and resends in 1400-byte packets. The download continues after a tiny delay.' },
      { label: 'If a firewall drops that ICMP', detail: 'The server never learns why its packets vanish, retransmits the same size, backs off, and the transfer hangs: a PMTUD black hole. Fix: allow the ICMP, or clamp MSS on the router.' },
    ],
  },
  misconceptions: [
    { myth: 'Blocking all ICMP is a harmless security measure.', truth: 'ICMP "fragmentation needed" is how path MTU discovery works. Blocking it creates black holes for large transfers.' },
    { myth: 'If ping works, MTU cannot be the problem.', truth: 'Default pings are 84 bytes. Test with `ping -M do -s 1472` to send full-size packets that may not be fragmented.' },
    { myth: 'Setting a larger MTU always makes things faster.', truth: 'Every device on the path must support it; a mismatch on one link drops large frames silently.' },
  ],
  checks: [
    { q: 'How many bytes of ping data fill a 1500-byte IPv4 packet?', a: '1472 (1500 − 20 IP header − 8 ICMP header).' },
    { q: 'SSH logs in fine but `cat bigfile` hangs. What do you suspect?', a: 'An MTU problem on the path with ICMP "fragmentation needed" filtered: a PMTUD black hole.' },
    { q: 'What is the TCP MSS on a normal Ethernet link?', a: '1460 bytes (1500 − 20 IP − 20 TCP).' },
    { q: 'Name two fixes for a black hole.', a: 'Allow ICMP fragmentation-needed / packet-too-big through the firewall, or clamp the TCP MSS on the router; or make the MTUs match.' },
  ],
};

export const TLS_PRIMER: Primer = {
  oneLiner: '**TLS** encrypts a connection and proves the server is who it claims to be, using a **certificate**: a public key with a name, signed by a **certificate authority** the client already trusts.',
  analogy: `
A certificate is a passport. It shows a name (www.corp.lab, srv01.corp.lab), a photo (the public key), an expiry date and a stamp from an issuing authority. You trust the passport because you trust the authority that issued it, not because the holder says so.

A **chain** is "this passport was issued by a regional office, and the regional office is accredited by the ministry". Your browser carries the list of ministries it trusts (the **root CAs**). If the regional office's accreditation letter (the intermediate certificate) is missing, the passport cannot be checked.`,
  ideas: [
    {
      title: 'What a certificate says',
      explain: 'Subject (who), **Subject Alternative Names** (the host names it is valid for), issuer (who signed it), validity dates, the public key, and the issuer\'s signature.',
      example: 'srv01\'s certificate: subject CN=www.corp.lab, SANs www.corp.lab and srv01.corp.lab, issuer "Corp Lab Issuing CA 1", valid Jun 2026 – Jul 2027.',
    },
    {
      title: 'The chain of trust',
      explain: 'Servers send their certificate **plus the intermediates**. The client follows the chain up to a **root** it has in its trust store. Missing intermediate, unknown root or a broken signature = verification fails.',
      example: '`openssl s_client -connect srv01.corp.lab:443` shows the chain the server sends:\n```\ndepth=2 C = US, O = Corp Lab, CN = Corp Lab Root CA\ndepth=1 C = US, O = Corp Lab, CN = Corp Lab Issuing CA 1\ndepth=0 CN = www.corp.lab\nVerification: OK\n```',
    },
    {
      title: 'The name must match',
      explain: 'The client checks that the name it connected to is in the certificate\'s SANs. A valid certificate for another name is still rejected.',
      example: '`curl https://srv01.corp.lab/` works (srv01.corp.lab is in the SANs). `curl -I https://10.0.20.10/` fails: "curl: (60) SSL: no alternative certificate subject name matches target host name \'10.0.20.10\'". The address is not in the certificate.',
    },
    {
      title: 'Certificate and private key belong together',
      explain: 'The server proves it owns the certificate by using the matching **private key** in the handshake. nginx refuses to start with a key that does not match its certificate.',
      example: 'After a renewal, copying the new certificate but keeping the old key makes `nginx -t` fail with "key values mismatch". The site goes down at the next reload.',
    },
  ],
  walkthrough: {
    title: 'curl opens https://srv01.corp.lab/',
    steps: [
      { label: 'TCP connection', detail: 'Normal handshake to 10.0.20.10:443.' },
      { label: 'ClientHello', detail: 'curl offers TLS versions and ciphers and names the site it wants (SNI: srv01.corp.lab).' },
      { label: 'Server sends its certificate chain', detail: 'nginx answers with its certificate for www.corp.lab / srv01.corp.lab and the intermediate "Corp Lab Issuing CA 1", and proves possession of the private key.' },
      { label: 'curl verifies', detail: 'Dates valid? Name srv01.corp.lab in the SANs? Chain ends at a root in /etc/ssl/certs (Corp Lab Root CA, installed with update-ca-certificates)? All yes.' },
      { label: 'Encrypted request', detail: 'Keys are agreed (X25519), the HTTP request travels encrypted, and curl prints the response.', show: 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nVerify return code: 0 (ok)' },
    ],
  },
  misconceptions: [
    { myth: '`curl -k` fixes certificate errors.', truth: '`-k` turns verification off. Fine for a quick test, but it hides exactly the problem (expiry, name, chain) you need to fix.' },
    { myth: 'If it works in my browser, the server configuration is right.', truth: 'Browsers cache intermediates and may fetch missing ones; command-line clients and other servers do not. Test with openssl s_client.' },
    { myth: 'Encryption means the server is trustworthy.', truth: 'TLS proves the server holds a key certified for that name and encrypts the traffic. It says nothing about what the site does.' },
  ],
  checks: [
    { q: 'Where does a client check which names a certificate is valid for?', a: 'The Subject Alternative Name (SAN) extension.' },
    { q: 'openssl s_client says "unable to get local issuer certificate". Two possible causes?', a: 'The server does not send the intermediate certificate, or the client does not trust the root CA.' },
    { q: 'Why does nginx refuse to start after a certificate renewal?', a: 'Often the new certificate does not match the private key configured next to it.' },
    { q: 'What does `-k` do in curl?', a: 'Skips certificate verification (insecure).' },
  ],
};
