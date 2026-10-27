import type { Lesson } from '../types';

export const NAT_LESSON: Lesson = {
  id: 'nat',
  moduleId: 'A',
  title: 'NAT: masquerade and port forwarding',
  level: 'intermediate',
  summary: 'Why private networks need address translation, how source NAT (masquerade) and destination NAT (port forwarding) rewrite packets, how conntrack reverses the translation for replies, and where NAT sits relative to filtering.',
  concepts: ['net.nat', 'net.routing', 'fw.stateful', 'fw.path'],

  what: `
**Network Address Translation (NAT)** means a router rewrites the addresses (and often the ports) in packets as they pass through it. You have almost certainly used it: your home router does it for every phone and laptop in the house.

### Why NAT exists
There are only about four billion IPv4 addresses, far too few for every device in the world. So organisations number their internal networks from the **private ranges** defined in RFC 1918: 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16. These addresses are not routed on the Internet; anyone can reuse them inside their own network. Only these three ranges are "private" in the RFC 1918 sense. Other special ranges look similar but are something else: **169.254.0.0/16** is *link-local* (an address a computer gives itself when DHCP fails, valid only on its own network segment), **127.0.0.0/8** is loopback, and **192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24** are reserved for documentation and examples. When an inside device talks to the Internet, the router replaces the private address with one of the organisation's few **public addresses**, and reverses the change on the replies.

This builds on the [IP networking lesson](#/lesson/ipnet/what) (routing, gateways) and on ports from [Transport and DNS](#/lesson/transport/what): NAT changes exactly those addresses and ports.

### Two directions
- **Source NAT (SNAT), often as masquerade**: for connections that start **inside** and go out. They leave with the router's public address as the source, so the outside world only ever sees the router. *Masquerade* is SNAT that automatically uses whatever address the outgoing interface has, which is handy when that address comes from DHCP and may change. Choose between the two like this:
  - The uplink address is **dynamic** (DHCP, PPPoE): use \`masquerade\`. It looks up the interface address for every new connection, and it forgets its translations when the interface goes down, so a new address works straight away.
  - The uplink address is **fixed**: \`snat to 203.0.113.2\` does the same job with a fixed address and slightly less work per connection.
- **Destination NAT (DNAT), also called port forwarding**: for connections that start **outside** and come in. A connection to the public address (on a given port) is redirected to a server inside. This is how a web server with a private address is **published** on the Internet.

### In the lab
rtr01 has a third interface, **eth2**, on the "Internet" network 203.0.113.0/24, with the address **203.0.113.2**. (203.0.113.0/24 is a range reserved for documentation, standing in here for real public addresses.) Its firewall ruleset contains a \`table ip nat\` with two rules:
- \`oifname "eth2" masquerade\`: everything leaving through eth2 gets rtr01's public address as source;
- \`iifname "eth2" tcp dport 80 dnat to 10.0.20.10:80\`: web requests arriving on eth2 are sent on to srv01.

**ext01** (203.0.113.80) is a host on that "Internet" with no route to any private network, just like a real Internet host.

> What the simulator models: nftables NAT chains (prerouting and postrouting, masquerade, snat and dnat with an optional port), translation entries per connection that reverse replies automatically, the conntrack listing, the correct order relative to the filter hooks, and notes on each hop that show every rewrite. It does not reverse-translate ICMP error messages, and it does not model masquerade port collisions.
`,

  internals: `
### Where NAT happens inside the router
On Linux, packet filtering and NAT are done by **netfilter**, which inspects packets at fixed points on their way through the kernel, called **hooks**. NAT uses two of them: **prerouting** (just after a packet arrives) and **postrouting** (just before it leaves).

\`\`\`
              prerouting            forward               postrouting
 eth2 in ──▶ [DNAT: change dst] ──▶ routing ──▶ [filter] ──▶ [SNAT/masquerade: change src] ──▶ eth1/eth0 out
                                    │
                                    └──▶ input (local)    output ──▶ postrouting
\`\`\`

The order matters:
- **DNAT happens in prerouting, before the routing decision.** The router needs to know the real destination to choose the right outgoing interface.
- **SNAT and masquerade happen in postrouting, after the routing decision and after filtering.** By then the outgoing interface is known, so masquerade can use its address.
- **The result:** the forward filter, which sits between the two, sees the **inside addresses**: the DNAT destination (10.0.20.10:80, not 203.0.113.2:80) and the original private source (10.0.10.25, not 203.0.113.2). Firewall rules in the forward chain must therefore be written for those addresses. This is one of the most common NAT mistakes.

:::practice
Q: A router forwards public TCP 2222 to an inside server with \`dnat to 10.0.20.30:22\`. The forward chain has policy drop. Which destination address and port must the forward rule match?
A: The **translated** ones: \`ip daddr 10.0.20.30 tcp dport 22\`. DNAT already happened in prerouting, so the forward filter never sees port 2222.
Q: Why can masquerade only run in postrouting and not in prerouting?
A: Masquerade uses the address of the **outgoing** interface, and the outgoing interface is only known after the routing decision, which comes after prerouting.
:::

### Only the first packet looks at the NAT rules
The kernel tracks every connection in its **connection tracking table** (conntrack). NAT rules are only checked for the **first packet** of a connection (conntrack state NEW). The decision is saved with the connection, and every later packet of that flow, in both directions, is translated the same way without looking at the rules again.

That is why changing a NAT rule does not affect connections that are already open. They keep their old translation until they end, or until you clear them with \`conntrack -F\`.

:::practice
Q: You fix a port forward rule, but a client that has an SSH session open through the old rule still reaches the old server. Is the fix broken?
A: No. Its connection was translated when it started, and that decision is stored in conntrack. **New** connections use the fixed rule; the old one keeps its translation until it ends or its conntrack entry is cleared.
Q: Why is \`conntrack -F\` risky on a busy production router?
A: It clears **every** tracked connection, not just the one you are testing, which can break all translated connections passing through the router.
:::

### Replies are translated back automatically
Here is an outbound web request with masquerade, hop by hop:
\`\`\`
ws01 → rtr01:   10.0.10.25:52088  → 203.0.113.80:80
rtr01 → ext01:  203.0.113.2:52088 → 203.0.113.80:80     (source rewritten)
ext01 → rtr01:  203.0.113.80:80   → 203.0.113.2:52088
rtr01 → ws01:   203.0.113.80:80   → 10.0.10.25:52088    (destination rewritten back)
\`\`\`

Inbound with DNAT, the mirror image happens: the destination is rewritten on the way in, and the **source of the reply** is rewritten back to the public address on the way out. This is essential, because a client only accepts a reply that comes from the address it contacted. If a reply arrived from 10.0.20.10 instead of 203.0.113.2, the client's TCP stack would ignore it.

:::practice
Q: An inside web server 10.0.20.10 is published as 203.0.113.2:80. Its reply leaves the router towards an Internet client. What is the reply's source address on the Internet side?
A: **203.0.113.2**, port 80. The router rewrites the reply's source back to the public address, because the client only accepts replies from the address it contacted.
Q: Why would a client ignore a reply that arrived with source 10.0.20.10 instead of 203.0.113.2?
A: Its TCP connection is with 203.0.113.2. A packet from another address does not belong to any connection it knows, so its TCP stack discards it.
:::

### conntrack shows both directions
\`\`\`
tcp 6 117 ESTABLISHED src=10.0.10.25 dst=203.0.113.80 sport=52088 dport=80 src=203.0.113.80 dst=203.0.113.2 sport=80 dport=52088 [ASSURED]
\`\`\`
Each entry has two sets of addresses and ports. The first is the packet as it arrived (the **original** direction). The second is the **reply** the router expects. If the second is simply the first with source and destination swapped, nothing was translated. Here it is not: the reply is expected at 203.0.113.2, so the source was masqueraded.

:::practice
Q: A conntrack entry reads \`src=10.0.30.7 dst=198.51.100.9 sport=40112 dport=443 src=198.51.100.9 dst=10.0.30.7 sport=443 dport=40112 [UNREPLIED]\`. Was the connection translated, and what does UNREPLIED suggest?
A: Not translated: the reply part is the original with source and destination simply swapped, so the router expects replies at the **private** address. Combined with [UNREPLIED], this points to **missing masquerade**: the remote side cannot reply to 10.0.30.7.
Q: For an inbound port forward, which half of the conntrack entry shows the inside server's address?
A: The **reply** half: its source is the inside server (the DNAT target), while the original half still shows the public address the client connected to.
:::

`,

  deployment: [
    {
      id: 'nft-nat',
      platform: 'Linux router: nftables NAT',
      summary: 'Turn a Debian machine with two interfaces into a NAT router for a private LAN and publish one internal service. Steps marked "simulated" work on rtr01 in the sandbox.',
      prerequisites: ['Debian 12 with an inside interface (eth0, 10.0.10.1/24) and an uplink (eth2) with a public or upstream address.', 'nftables installed and enabled.', 'Console access: a firewall mistake can lock out SSH.'],
      steps: [
        { title: 'Enable routing', command: 'echo "net.ipv4.ip_forward = 1" | sudo tee /etc/sysctl.d/99-forward.conf\nsudo sysctl --system\nsysctl net.ipv4.ip_forward', what: 'Allows the kernel to forward packets between interfaces, persistently.', why: 'Without forwarding, NAT has nothing to translate.', expected: 'net.ipv4.ip_forward = 1', simulated: true },
        { title: 'Add the NAT table', command: 'sudoedit /etc/nftables.conf\n\ntable ip nat {\n\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n\t\tiifname "eth2" tcp dport 80 dnat to 10.0.20.10:80\n\t}\n\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t\toifname "eth2" masquerade\n\t}\n}', what: 'Masquerades everything leaving the uplink and forwards public port 80 to the web server.', why: 'nat chains need "type nat" and the dstnat/srcnat priorities. Policy accept in nat chains only means "do not translate".', expected: '', simulated: true },
        { title: 'Filter what is forwarded', command: '\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t\tct state established,related accept\n\t\tiifname "eth0" oifname "eth2" accept\n\t\tiifname "eth2" ip daddr 10.0.20.10 tcp dport 80 accept\n\t}', what: 'Allows LAN → Internet, the published web server, and replies.', why: 'Note the inside address and port in the inbound rule: DNAT has already happened when the forward hook runs.', expected: '', simulated: true },
        { title: 'Load and check', command: 'sudo nft -c -f /etc/nftables.conf && sudo systemctl reload nftables\nsudo nft list table ip nat', what: 'Validates, then loads the ruleset atomically.', why: 'A syntax error leaves the old ruleset active instead of none.', expected: 'table ip nat {\n\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n\t\tiifname "eth2" tcp dport 80 dnat to 10.0.20.10:80\n\t}\n...', simulated: true },
        { title: 'Test both directions', command: '# inside → outside (on ws01)\ncurl -I http://203.0.113.80/\n# outside → published service (on ext01)\ncurl -I http://203.0.113.2/\n# on the router\nsudo conntrack -L', what: 'One outbound and one inbound connection, then the translation table.', why: 'Always test a published service from OUTSIDE: from inside it may work for other reasons (or fail because of hairpinning).', expected: 'HTTP/1.1 200 OK\n...\ntcp  6 117 ESTABLISHED src=203.0.113.80 dst=203.0.113.2 sport=57920 dport=80 src=10.0.20.10 dst=203.0.113.80 sport=80 dport=57920 [ASSURED] mark=0 use=1', simulated: true },
        { title: 'Watch translation on the wire', command: 'sudo tcpdump -n -i eth0 tcp port 80\nsudo tcpdump -n -i eth2 tcp port 80', what: 'Capture the same flow on both sides of the router.', why: 'The inside capture shows private addresses, the uplink capture the public one: the clearest proof NAT is (or is not) applied.', expected: 'eth0: IP 10.0.10.25.58318 > 203.0.113.80.80: Flags [S] ...\neth2: IP 203.0.113.2.58318 > 203.0.113.80.80: Flags [S] ...', simulated: true },
      ],
    },
    {
      id: 'iptables',
      platform: 'Linux: the same with iptables (legacy syntax)',
      summary: 'Many guides and older systems use iptables; on Debian 12 these commands are translated to nftables by iptables-nft.',
      prerequisites: ['iptables package.'],
      steps: [
        { title: 'Masquerade and port forward', command: 'sudo iptables -t nat -A POSTROUTING -o eth2 -j MASQUERADE\nsudo iptables -t nat -A PREROUTING -i eth2 -p tcp --dport 80 -j DNAT --to-destination 10.0.20.10:80\nsudo iptables -A FORWARD -i eth2 -d 10.0.20.10 -p tcp --dport 80 -j ACCEPT\nsudo iptables -t nat -L -n -v', what: 'Same three rules in iptables syntax.', why: 'Recognising both syntaxes matters when reading existing systems; do not mix iptables and nft rules on one host.', expected: 'Chain POSTROUTING (policy ACCEPT)\n pkts bytes target     prot opt in  out   source    destination\n   12   720 MASQUERADE all  --  *   eth2  0.0.0.0/0 0.0.0.0/0' },
      ],
    },
    {
      id: 'windows-nat',
      platform: 'Windows',
      summary: 'Windows offers NAT mostly for Hyper-V/containers and simple port proxies.',
      prerequisites: ['Windows 10/11 or Server with Hyper-V.'],
      steps: [
        { title: 'NAT for an internal virtual switch', command: 'New-VMSwitch -Name LabNAT -SwitchType Internal\nNew-NetIPAddress -IPAddress 192.168.100.1 -PrefixLength 24 -InterfaceAlias "vEthernet (LabNAT)"\nNew-NetNat -Name LabNAT -InternalIPInterfaceAddressPrefix 192.168.100.0/24\nGet-NetNat', what: 'Creates a NAT network for VMs (masquerade behind the host\'s address).', why: 'Common for lab environments on a laptop.', expected: 'Name                             : LabNAT\nInternalIPInterfaceAddressPrefix : 192.168.100.0/24\nActive                           : True' },
        { title: 'Port forward to a VM', command: 'Add-NetNatStaticMapping -NatName LabNAT -Protocol TCP -ExternalIPAddress 0.0.0.0 -ExternalPort 8080 -InternalIPAddress 192.168.100.10 -InternalPort 80', what: 'DNAT of host port 8080 to a VM\'s port 80.', why: 'The Windows equivalent of a dnat rule.', expected: '' },
      ],
    },
  ],

  configIntro: `
NAT rules live in nftables chains of type \`nat\`, separate from the filter rules. The NAT inspector below sends one connection through a fresh copy of the lab and shows the same flow on both sides of rtr01, together with the router's conntrack table, so you can see the packet before and after translation.
`,


  configFiles: [
    {
      platform: 'Linux',
      items: [
        { path: '/etc/nftables.conf', purpose: 'table ip nat { prerouting (dnat), postrouting (snat/masquerade) } next to the filter table.' },
        { path: '/etc/sysctl.d/*.conf', purpose: 'net.ipv4.ip_forward = 1 (persistent).' },
        { path: 'conntrack -L / conntrack -F', purpose: 'List / flush tracked flows including their translations.' },
        { path: 'nft list table ip nat', purpose: 'Active NAT rules.' },
      ],
    },
  ],

  directives: [
    { name: 'type nat hook prerouting priority dstnat', compiledDefault: '(chain must be created)', recommended: 'One per family/table', explanation: 'Where DNAT rules go. Runs before routing.', security: 'A DNAT rule publishes an inside service: pair it with a narrow forward rule.' },
    { name: 'type nat hook postrouting priority srcnat', compiledDefault: '(chain must be created)', recommended: 'One per family/table', explanation: 'Where SNAT/masquerade rules go. Runs after routing and filtering.', security: '' },
    { name: 'masquerade', compiledDefault: '', recommended: 'On the uplink when its address is dynamic', explanation: 'SNAT to the address of the outgoing interface, looked up per new connection.', security: 'Restrict with oifname so internal traffic is not translated.' },
    { name: 'snat to ADDR', compiledDefault: '', recommended: 'On uplinks with a static public address', explanation: 'SNAT to a fixed address.', security: '' },
    { name: 'dnat to ADDR[:PORT]', compiledDefault: '', recommended: 'Match iifname + protocol + port', explanation: 'Rewrite the destination (and optionally port) of new inbound connections.', security: 'A DNAT without a port match forwards EVERY port to the inside host.' },
    { name: 'net.ipv4.ip_forward', compiledDefault: '0', recommended: '1 on routers only', explanation: 'Enables routing between interfaces.', security: 'A host with forwarding on and a permissive forward chain is a router for anyone who points a route at it.' },
  ],

  troubleshootingIntro: `
### Capture on both sides of the router
NAT changes packets inside the router, so the most useful evidence is a comparison: what the packet looks like when it arrives, and what it looks like when it leaves.

1. **Does the router route at all?** \`sysctl net.ipv4.ip_forward\` must show 1. If it is 0, NAT rules make no difference.
2. **Outbound: does the packet leave translated?** Run \`tcpdump -n -i eth2\` on the router while you test. A private source address on the Internet-facing interface means masquerade is missing or does not match. Nothing at all means the packet was dropped in the forward chain: check which rule's counters go up with \`nft -a list ruleset\`.
3. **Inbound: does the packet reach the inside server?** Run \`tcpdump\` on the server. Nothing arrives: look at the forward filter (remember, it sees the translated address) or a wrong DNAT target. The SYN arrives but there is no answer: look at the server's own firewall or its route back.
4. **What did conntrack record?** \`conntrack -L\` lists the connections. Compare the original and reply directions. A DNAT entry pointing at an unexpected address leads you straight to the faulty rule.
5. **Old connections:** after changing NAT rules, existing connections keep their old translation. On a lab router, \`conntrack -F\` clears them. Be careful in production: it resets every tracked connection, not just the one you are testing.

### Typical mistakes
- **No masquerade:** packets leave with private source addresses. The remote side cannot send replies to 10.x addresses (on the real Internet, providers drop such packets), so outbound connections time out.
- **Wrong DNAT target:** the router faithfully forwards to an address that does not exist (ARP fails, and the router sends ICMP host unreachable) or to the wrong port (a reset comes back: "Connection refused").
- **Filtering on the public port:** a forward rule matching \`dport 8080\`, when 8080 is translated to port 80, never matches, because the filter sees port 80. Match the inside address and port instead (or, on a real system, \`ct status dnat\`).
- **Hairpin NAT:** inside clients that use the **public** address of an inside server need an extra SNAT rule, so that replies return through the router (not modelled in the simulator).
- **ip_forward=0:** if the router does not route, its NAT rules are never reached.

`,

  errorMap: [
    { message: 'Outbound connections time out; tcpdump on the uplink shows 10.x sources', layer: 'NAT (source)', meaning: 'Masquerade (SNAT) is missing, or its rule names a different interface, so private addresses leave untranslated and replies never come back.', firstCheck: 'nft list table ip nat: oifname of the masquerade rule' },
    { message: 'Port forward times out; inside server sees nothing', layer: 'Filter after DNAT', meaning: 'The forward chain drops the packet. Remember that it sees the already-translated inside address and port.', firstCheck: 'nft -a list ruleset: which rule counters increase?' },
    { message: 'Port forward: "No route to host" from outside', layer: 'NAT (destination)', meaning: 'The DNAT target does not exist; the router\'s ARP fails and it sends ICMP host unreachable.', firstCheck: 'dnat to … address; ip neigh on the router' },
    { message: 'Port forward: "Connection refused"', layer: 'NAT target service', meaning: 'The DNAT rule points at the wrong port, or no service listens on that port on the inside server.', firstCheck: 'ss -tlnp on the inside server' },
    { message: 'Works from outside, not from inside using the public address', layer: 'Hairpin NAT', meaning: 'Inside clients reach the inside server through its public address, but the server replies directly, bypassing the router, so the client ignores the reply.', firstCheck: 'Use internal DNS (split horizon) or add hairpin SNAT' },
  ],

  scenarioIds: ['nat-no-masquerade', 'nat-dnat-typo', 'nat-filter-order'],
  assessmentId: 'nat',
  references: [
    { title: 'RFC 1918: Address Allocation for Private Internets', url: 'https://www.rfc-editor.org/rfc/rfc1918' },
    { title: 'RFC 3022: Traditional IP Network Address Translator', url: 'https://www.rfc-editor.org/rfc/rfc3022' },
    { title: 'RFC 4787: NAT Behavioral Requirements for Unicast UDP', url: 'https://www.rfc-editor.org/rfc/rfc4787' },
    { title: 'nftables wiki: Performing Network Address Translation', url: 'https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)' },
    { title: 'nftables wiki: Netfilter hooks', url: 'https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks' },
    { title: 'conntrack(8)', url: 'https://manpages.debian.org/bookworm/conntrack/conntrack.8.en.html' },
  ],
};
