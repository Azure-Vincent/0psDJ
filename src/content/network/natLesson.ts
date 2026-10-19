import type { Lesson } from '../types';

export const NAT_LESSON: Lesson = {
  id: 'nat',
  moduleId: 'A',
  title: 'NAT: masquerade and port forwarding',
  level: 'intermediate',
  summary: 'Why private networks need address translation, how source NAT (masquerade) and destination NAT (port forwarding) rewrite packets, how conntrack reverses the translation for replies, and where NAT sits relative to filtering.',
  concepts: ['net.nat', 'net.routing', 'fw.stateful', 'fw.path'],

  what: `
**Network Address Translation** rewrites the addresses (and often ports) of packets as they pass a router. It exists mainly because IPv4 addresses are scarce: organisations number their internal networks from the **private ranges** (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), which are not routed on the Internet, and share one or a few **public addresses**.

### Two directions
- **Source NAT (SNAT / masquerade)**: outbound connections from inside hosts leave with the router's public address as source. The outside world only ever sees the router. *Masquerade* is SNAT that automatically uses the address of the outgoing interface (useful when that address is assigned by DHCP).
- **Destination NAT (DNAT / port forwarding)**: inbound connections to the public address (on a given port) are redirected to an inside server. This is how a web server on a private address is **published**.

### What NAT is not
NAT is not a firewall: it hides addresses as a side effect, but a forwarding router still forwards anything you route to it. Filtering rules decide what is allowed. With IPv6 there are enough addresses that NAT is generally not used; firewalls do the job instead.

### In the lab
rtr01 has a third interface **eth2** on the "Internet" 203.0.113.0/24 (a documentation range standing in for public addresses) with **203.0.113.2**. Its ruleset has a \`table ip nat\`: \`oifname "eth2" masquerade\` and \`iifname "eth2" tcp dport 80 dnat to 10.0.20.10:80\`. **ext01** (203.0.113.80) is a host on the Internet with no route to private networks: exactly like a real Internet host.

> The simulator implements nftables nat chains (prerouting/postrouting, masquerade, snat/dnat with optional port), per-flow translation entries that reverse replies automatically, conntrack listing, the correct ordering relative to the filter hooks, and the hop notes that show each rewrite. ICMP error messages are not reverse-translated, and port-collision handling for masquerade is not modelled.
`,

  internals: `
### Where NAT happens in netfilter
\`\`\`
              prerouting            forward               postrouting
 eth2 in ──▶ [DNAT: change dst] ──▶ routing ──▶ [filter] ──▶ [SNAT/masquerade: change src] ──▶ eth1/eth0 out
                                    │
                                    └──▶ input (local)    output ──▶ postrouting
\`\`\`
- **DNAT happens in prerouting, BEFORE the routing decision**: the router must know the real destination to choose the outgoing interface.
- **SNAT/masquerade happens in postrouting, AFTER the routing decision and AFTER filtering**: the outgoing interface is known, so masquerade can use its address.
- **Consequence:** the **forward filter sees the inside addresses**: the DNATed destination (10.0.20.10:80, not 203.0.113.2:80) and the original private source (10.0.10.25, not 203.0.113.2). Forward rules must be written for those.

### Only the first packet consults the NAT rules
nat chains are evaluated for the **first packet of a connection** (conntrack state NEW). The decision is stored with the conntrack entry, and every later packet of the flow, in both directions, is translated the same way without looking at the rules again. That is why changing a NAT rule does not affect existing connections (flush them with \`conntrack -F\` or wait for them to end).

### Replies are reversed automatically
Outbound with masquerade:
\`\`\`
ws01 → rtr01:   10.0.10.25:52088  → 203.0.113.80:80
rtr01 → ext01:  203.0.113.2:52088 → 203.0.113.80:80     (source rewritten)
ext01 → rtr01:  203.0.113.80:80   → 203.0.113.2:52088
rtr01 → ws01:   203.0.113.80:80   → 10.0.10.25:52088    (destination rewritten back)
\`\`\`
Inbound with DNAT the mirror image happens: the destination is rewritten on the way in and the **source of the reply** is rewritten back to the public address on the way out. The client must see the reply come from the address it contacted, otherwise its TCP stack ignores it.

### conntrack shows both tuples
\`\`\`
tcp 6 117 ESTABLISHED src=10.0.10.25 dst=203.0.113.80 sport=52088 dport=80 src=203.0.113.80 dst=203.0.113.2 sport=80 dport=52088 [ASSURED]
\`\`\`
The first tuple is the packet as it arrived (original direction); the second is the **expected reply**. When they are not mirror images, the flow is translated: here the reply goes to 203.0.113.2, so the source was masqueraded.

### Typical mistakes
- **No masquerade:** private source addresses leave on the uplink; the remote side cannot route replies to 10.x (on the real Internet, providers drop such packets). Outbound connections time out.
- **Wrong DNAT target:** the router faithfully forwards to an address that does not exist (ARP fails → ICMP host unreachable) or to the wrong port (RST → refused).
- **Filtering the public address:** a forward rule matching \`dport 8080\` when 8080 is DNATed to port 80 never matches: the filter sees port 80. Match the inside address/port (or, on a real system, \`ct status dnat\`).
- **Hairpin NAT:** inside clients using the public address of an inside server need an extra SNAT rule so replies return through the router (not modelled here).
- **ip_forward=0:** NAT rules are irrelevant if the router does not route at all.
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
NAT rules live in nat-type chains. The NAT inspector below runs one connection through a fresh lab and shows the same flow on each side of rtr01, plus the router's conntrack table: the before/after of translation.
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
1. **Is the router routing?** \`sysctl net.ipv4.ip_forward\`.
2. **Does the packet leave translated?** \`tcpdump -n -i eth2\` while testing. A private source address on the uplink = no masquerade. Nothing at all = dropped in forward (check counters with \`nft -a list ruleset\`).
3. **Inbound: does the packet reach the inside server?** \`tcpdump\` on the server. Nothing → forward filter (remember it sees the translated packet) or a wrong DNAT target. SYN arrives but no answer → the server's own firewall or its route back.
4. **What did conntrack record?** \`conntrack -L\`: compare the original and reply tuples. A DNAT entry to an unexpected address points straight at the rule.
5. **Old flows:** after changing NAT rules, existing connections keep their translation. \`conntrack -F\` on a lab router (careful in production: it resets every tracked flow).
`,

  errorMap: [
    { message: 'Outbound connections time out; tcpdump on the uplink shows 10.x sources', layer: 'NAT (source)', meaning: 'Masquerade/SNAT missing or not matching the interface.', firstCheck: 'nft list table ip nat: oifname of the masquerade rule' },
    { message: 'Port forward times out; inside server sees nothing', layer: 'Filter after DNAT', meaning: 'Forward chain drops the (already translated) packet.', firstCheck: 'nft -a list ruleset: which rule counters increase?' },
    { message: 'Port forward: "No route to host" from outside', layer: 'NAT (destination)', meaning: 'The DNAT target does not exist; the router\'s ARP fails and it sends ICMP host unreachable.', firstCheck: 'dnat to … address; ip neigh on the router' },
    { message: 'Port forward: "Connection refused"', layer: 'NAT target service', meaning: 'Wrong target port or service not listening there.', firstCheck: 'ss -tlnp on the inside server' },
    { message: 'Works from outside, not from inside using the public address', layer: 'Hairpin NAT', meaning: 'Replies bypass the router.', firstCheck: 'Use internal DNS (split horizon) or add hairpin SNAT' },
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
