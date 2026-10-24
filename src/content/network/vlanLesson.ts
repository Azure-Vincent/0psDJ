import type { Lesson } from '../types';

export const VLAN_LESSON: Lesson = {
  id: 'vlan',
  moduleId: 'A',
  title: 'VLANs, trunks and inter-VLAN routing',
  level: 'intermediate',
  summary: 'How one switch carries several separate broadcast domains: access and trunk ports, 802.1Q tags, the PVID/native VLAN, MAC learning per VLAN, and routing between VLANs with router-on-a-stick sub-interfaces.',
  concepts: ['net.vlan', 'net.arp', 'net.routing'],

  what: `
A **VLAN** (virtual LAN) splits one physical switch into several independent **broadcast domains**. Hosts in VLAN 10 and VLAN 20 may be plugged into the same switch, but an ARP broadcast from VLAN 10 never reaches VLAN 20: at layer 2 they are separate networks. Traffic between VLANs must be **routed** (a router or layer-3 switch), which is exactly where firewall rules can be applied.

### Why
- **Segmentation and security**: servers, office PCs, guests, phones and management interfaces in separate subnets with policy between them.
- **Smaller broadcast domains**: less ARP/DHCP noise, smaller failure domains.
- **Flexibility**: the VLAN of a port is configuration, not cabling. Moving a desk means reconfiguring one port.

### Two kinds of ports
- **Access port**: belongs to one VLAN; frames are sent and received **untagged**. The connected host knows nothing about VLANs. Used for PCs, printers, servers.
- **Trunk port**: carries several VLANs over one link; frames carry an **802.1Q tag** (VLAN ID) so the receiver can tell them apart. Used between switches, and to routers or hypervisors that serve several VLANs. One VLAN per trunk may be **untagged** (the *native VLAN* / PVID).

### In the lab
**sw01** is a Debian switch running a **VLAN-aware Linux bridge** (br0), configured with ifupdown2 like Cumulus Linux or Debian: VLAN 10 office (ws01, ws02, ns1), VLAN 20 servers (srv01), VLAN 30 development (dev01). rtr01 connects to VLAN 10 and 20 with two access ports and to VLAN 30 through a **trunk** (eth3, tagged 30) using the sub-interface **eth3.30**: *router-on-a-stick*.

> The simulator models access and trunk ports (bridge-access, bridge-vids, bridge-pvid), untagged vs tagged membership, VLAN sub-interfaces on hosts (eth3.30, ip link add … type vlan), MAC learning per VLAN (bridge fdb), 802.1Q tags in tcpdump -e and PCAP export, and runtime vs persistent switch configuration. Spanning tree, Q-in-Q, LACP and VLAN-unaware bridges are not modelled; membership is treated as symmetric.
`,

  internals: `
### The 802.1Q tag
A tagged Ethernet frame inserts 4 bytes after the source MAC address:

\`\`\`
| dst MAC (6) | src MAC (6) | 0x8100 (TPID) | PCP(3) DEI(1) VID(12) | EtherType (e.g. 0x0800) | payload ... |
\`\`\`
- **TPID 0x8100** marks the frame as tagged.
- **VID** (12 bits): VLAN 1–4094 (0 and 4095 reserved).
- **PCP**: priority for QoS (voice), **DEI**: drop eligibility.
The tag adds 4 bytes, so trunks must allow frames of 1522 bytes.

### What the switch does with a frame (VLAN-aware Linux bridge)
**Ingress** (frame arrives on a port):
1. Untagged frame → assigned to the port's **PVID**. A port without a PVID drops untagged frames.
2. Tagged frame → kept in its VLAN **if the port is a member of that VLAN**, otherwise dropped (ingress filtering).

**Forwarding**: the bridge looks up the destination MAC **in the forwarding database of that VLAN** (learned from source MACs, per VLAN). Unknown unicast, broadcast and multicast are **flooded to every port that is a member of the VLAN**, never to other VLANs.

**Egress**: the frame leaves **untagged** on ports where the VLAN is marked *untagged* (access ports, the native VLAN of a trunk), **tagged** everywhere else.

### Linux bridge vocabulary (ifupdown2)
| Setting | Meaning |
|---|---|
| \`bridge-vlan-aware yes\` | enable VLAN filtering on the bridge |
| \`bridge-access 10\` | access port: VLAN 10, PVID 10, untagged |
| \`bridge-vids 10 20 30\` | VLANs a port carries tagged (on the bridge: default for ports) |
| \`bridge-pvid 1\` | VLAN for untagged frames, sent untagged (native VLAN) |
| \`bridge vlan show\` / \`bridge fdb show\` | runtime membership / learned MAC addresses per VLAN |
On Cisco IOS the same ideas are \`switchport mode access\` + \`switchport access vlan 10\`, and \`switchport mode trunk\` + \`switchport trunk allowed vlan 30\` + \`switchport trunk native vlan 1\`.

### Hosts on trunks: VLAN sub-interfaces
A Linux host (router, hypervisor) receives tagged frames on the physical NIC and delivers each VLAN to a **sub-interface**: \`eth3.30\` = VLAN 30 on eth3 (\`ip link add link eth3 name eth3.30 type vlan id 30\`, or an \`iface eth3.30\` stanza; Debian derives the VLAN ID from the name). Untagged frames on the trunk go to eth3 itself.

### Router-on-a-stick
rtr01 has one sub-interface per VLAN on the trunk, each with an address that is that VLAN's **default gateway** (10.0.30.1 on eth3.30). A packet from dev01 (VLAN 30) to srv01 (VLAN 20): dev01 → switch (untagged in, tagged 30 out on swp7) → rtr01 eth3.30 → routing decision, TTL−1, forward filter → eth1 (VLAN 20) → srv01. Between VLANs the rules of routing apply: different subnets, gateways, firewall.

`,

  deployment: [
    {
      id: 'linux-bridge',
      platform: 'Linux switch: VLAN-aware bridge with ifupdown2',
      summary: 'Configure a Debian box (or Cumulus Linux) with several ports as a VLAN-aware switch. Steps marked "simulated" work on sw01 in the sandbox.',
      prerequisites: ['Debian 12 with several NICs (or a VM with several virtual NICs) and the ifupdown2 package (replaces ifupdown).', 'Console access: a switch misconfiguration can cut you off.'],
      steps: [
        { title: 'Install ifupdown2', command: 'sudo apt install ifupdown2 bridge-utils', what: 'ifupdown2 understands the bridge-vlan-aware/bridge-access/bridge-vids options and can apply changes with ifreload.', why: 'Classic ifupdown would need post-up "bridge vlan add" commands for the same result.', expected: '' },
        { title: 'Describe the ports', command: 'sudoedit /etc/network/interfaces\n\nauto swp1\niface swp1\n    bridge-access 10\n\nauto swp7\niface swp7\n    bridge-vids 30\n\nauto br0\niface br0\n    bridge-vlan-aware yes\n    bridge-ports swp1 swp7\n    bridge-vids 10 20 30\n    bridge-pvid 1', what: 'swp1 = access port in VLAN 10; swp7 = trunk carrying VLAN 30 tagged plus the untagged PVID 1; br0 = the VLAN-aware bridge.', why: 'Port settings override the bridge defaults; each port\'s VLAN list is what it accepts and sends.', expected: '', simulated: true },
        { title: 'Apply and verify', command: 'sudo ifreload -a\nbridge vlan show', what: 'Applies the file to the running system and shows each port\'s VLANs, PVID and untagged flags.', why: 'ifreload only changes what differs; bridge vlan show is the source of truth for what the kernel does.', expected: 'port              vlan-id\nswp1              10 PVID Egress Untagged\nswp7              1 PVID Egress Untagged\n                  30', simulated: true },
        { title: 'Watch MAC learning', command: 'bridge fdb show | grep -v permanent', what: 'Lists which MAC address was learned on which port in which VLAN.', why: 'Finds a host and the VLAN it is really in: the fastest check for "wrong VLAN".', expected: '52:54:00:d4:00:19 dev swp1 vlan 10 master br0', simulated: true },
        { title: 'Runtime change (not persistent)', command: 'sudo bridge vlan add dev swp7 vid 40\nsudo bridge vlan del dev swp7 vid 40', what: 'Adds/removes a VLAN on a port immediately.', why: 'Useful for testing; lost at reboot or ifreload unless written to the file.', expected: '', simulated: true },
      ],
    },
    {
      id: 'router-subif',
      platform: 'Linux router: VLAN sub-interfaces (router-on-a-stick)',
      summary: 'Route between VLANs that arrive tagged on one NIC.',
      prerequisites: ['The switch port to the router configured as a trunk carrying the VLANs.', 'IP forwarding enabled.'],
      steps: [
        { title: 'Persistent sub-interface', command: 'sudoedit /etc/network/interfaces\n\nauto eth3\niface eth3 inet manual\n\nauto eth3.30\niface eth3.30 inet static\n    address 10.0.30.1/24', what: 'eth3 carries the trunk; eth3.30 is VLAN 30 with the gateway address.', why: 'Debian (vlan package or ifupdown2) creates VLAN 30 on eth3 from the name.', expected: '', simulated: true },
        { title: 'Create one by hand', command: 'sudo ip link add link eth3 name eth3.40 type vlan id 40\nsudo ip addr add 10.0.40.1/24 dev eth3.40\nsudo ip link set eth3.40 up\nip -d link show eth3.40', what: 'Runtime equivalent with iproute2.', why: 'The -d output shows the VLAN ID actually used: "vlan protocol 802.1Q id 40".', expected: '7: eth3.40@eth3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...\n    vlan protocol 802.1Q id 40 <REORDER_HDR>', simulated: true },
        { title: 'See the tags', command: 'sudo tcpdump -e -n -i eth3', what: 'Captures on the parent NIC with link-level headers.', why: 'Each frame shows "ethertype 802.1Q (0x8100), vlan 30": proof of what is on the trunk.', expected: '52:54:00:e7:00:1e > 52:54:00:a1:00:04, ethertype 802.1Q (0x8100), vlan 30, p 0, ethertype IPv4 (0x0800), IP 10.0.30.25 > 10.0.20.10: ICMP echo request ...', simulated: true },
      ],
    },
    {
      id: 'cisco-windows',
      platform: 'Cisco IOS switch and Windows / Hyper-V',
      summary: 'The same concepts in other common syntaxes.',
      prerequisites: ['Cisco Catalyst switch, or Windows Server with Hyper-V.'],
      steps: [
        { title: 'Cisco access and trunk', command: 'interface Gi1/0/8\n switchport mode access\n switchport access vlan 30\n!\ninterface Gi1/0/24\n switchport mode trunk\n switchport trunk allowed vlan 10,20,30\n switchport trunk native vlan 1\n!\nshow vlan brief\nshow interfaces trunk', what: 'Access port in VLAN 30; trunk carrying 10, 20, 30.', why: '"allowed vlan" is the Cisco equivalent of bridge-vids; "show interfaces trunk" shows what is actually forwarding.', expected: 'Port        Mode         Encapsulation  Status        Native vlan\nGi1/0/24    on           802.1q         trunking      1' },
        { title: 'Hyper-V VM in a VLAN', command: 'Set-VMNetworkAdapterVlan -VMName dev01 -Access -VlanId 30\nGet-VMNetworkAdapterVlan -VMName dev01', what: 'The virtual switch port of the VM becomes an access port in VLAN 30 (the host NIC must be on a trunk).', why: 'Hypervisors are switches too: VLAN problems often live there.', expected: 'VMName VMNetworkAdapterName Mode   VlanList\ndev01  Network Adapter      Access 30' },
      ],
    },
  ],

  configIntro: `
The switch configuration decides which broadcast domain every port belongs to. The VLAN explorer below edits a copy of sw01's port table, recomputes the broadcast domains with the simulator's own layer-2 code, and shows the ifupdown2 stanza for each port.
`,

  configFiles: [
    {
      platform: 'Linux switch (ifupdown2)',
      items: [
        { path: '/etc/network/interfaces', purpose: 'bridge-vlan-aware, bridge-ports, bridge-vids, bridge-pvid on the bridge; bridge-access / bridge-vids / bridge-pvid per port.' },
        { path: 'ifreload -a', purpose: 'Apply the file to the running system.' },
        { path: 'bridge vlan show / bridge fdb show / bridge link', purpose: 'Runtime membership, learned MACs per VLAN, port state.' },
      ],
    },
    {
      platform: 'Linux host / router',
      items: [
        { path: '/etc/network/interfaces (iface eth3.30 ...)', purpose: 'VLAN sub-interfaces with their addresses.' },
        { path: 'ip -d link show', purpose: 'VLAN ID and parent of each sub-interface.' },
        { path: 'tcpdump -e -i eth3', purpose: '802.1Q tags on the wire.' },
      ],
    },
  ],

  directives: [
    { name: 'bridge-vlan-aware yes', compiledDefault: 'no', recommended: 'yes for any multi-VLAN switch', explanation: 'Turns on VLAN filtering: ports only accept and send the VLANs configured on them.', security: 'Without it the bridge is one flat broadcast domain: no isolation at all.' },
    { name: 'bridge-access N', compiledDefault: '—', recommended: 'Every host-facing port', explanation: 'Port carries only VLAN N, untagged (PVID N).', security: 'Hosts on access ports cannot send into other VLANs (tagged frames for other VLANs are dropped).' },
    { name: 'bridge-vids LIST', compiledDefault: '—', recommended: 'Only the VLANs needed behind that trunk', explanation: 'VLANs carried tagged; on the bridge stanza: the default for ports.', security: 'Allowing all VLANs everywhere widens the blast radius of a compromised or misconfigured device.' },
    { name: 'bridge-pvid N (native VLAN)', compiledDefault: '1', recommended: 'An unused VLAN on trunks', explanation: 'VLAN assigned to untagged frames and sent untagged.', security: 'VLAN 1 as native is the classic "VLAN hopping" (double tagging) enabler; use an unused native VLAN or tag everything.' },
    { name: 'iface eth3.30 / ip link add … type vlan id 30', compiledDefault: '—', recommended: 'One per routed VLAN', explanation: 'Host-side VLAN sub-interface.', security: 'A host on a trunk can reach every VLAN on it: firewall between them.' },
  ],

  troubleshootingIntro: `
### Layer 2 first, then routing
1. **Is the gateway in my broadcast domain?** Ping it and look at \`ip neigh\`: FAILED = nobody answered ARP/NDP → layer 2 (VLAN) or the gateway itself.
2. **Which VLAN is the host really in?** On the switch: \`bridge fdb show\` (the VLAN its MAC was learned in) and \`bridge vlan show\` (the port's PVID). Compare with the plan.
3. **Is the VLAN carried towards the router?** \`bridge vlan show\` on the trunk port; \`tcpdump -e -n -i eth3\` on the router: tagged frames out, anything in?
4. **Does the router tag correctly?** \`ip -d link show\` on the router: "vlan protocol 802.1Q id 30".
5. **Persistent?** Compare \`bridge vlan show\` with /etc/network/interfaces; ifreload -a or a reboot will apply the file.

### Typical mistakes
- **Access port in the wrong VLAN**: link up, host correctly configured, but ARP for the gateway goes unanswered (the host may even get an address from another VLAN's DHCP server).
- **VLAN missing on a trunk** ("pruned"): a whole VLAN loses its gateway while hosts inside it still talk to each other.
- **Native VLAN mismatch**: two ends disagree on which VLAN is untagged; traffic leaks between VLANs or disappears.
- **Wrong sub-interface ID**: router tags with VLAN 3 instead of 30; looks healthy on the router.
- **Forgetting the runtime/persistent split**: \`bridge vlan add\` fixes it now, the file is what survives a reboot.

`,

  errorMap: [
    { message: 'Destination Host Unreachable (from the host itself) for its own gateway', layer: 'Layer 2 / VLAN', meaning: 'ARP for the gateway got no reply: wrong VLAN on the access port, VLAN not on the trunk, or wrong sub-interface ID.', firstCheck: 'bridge fdb show / bridge vlan show on the switch' },
    { message: 'Host gets an address from the wrong subnet via DHCP', layer: 'Layer 2 / VLAN', meaning: 'Its port is in another VLAN whose DHCP server answered.', firstCheck: 'The port\'s PVID on the switch' },
    { message: 'Hosts in one VLAN reach each other but not the gateway', layer: 'Trunk', meaning: 'The VLAN is not carried (or wrongly tagged) towards the router.', firstCheck: 'bridge vlan show on the trunk port; ip -d link on the router' },
    { message: 'Link up, interface UP, address correct, nothing works', layer: 'Layer 2', meaning: 'Physical layer is fine; VLAN membership is not.', firstCheck: 'tcpdump on the host: do broadcasts from expected neighbours arrive?' },
    { message: 'Works until the switch reboots', layer: 'Configuration', meaning: 'Fixed at runtime (bridge vlan add) but not in the configuration file.', firstCheck: 'Compare bridge vlan show with /etc/network/interfaces' },
  ],

  scenarioIds: ['vlan-access-port', 'vlan-trunk-pruned', 'vlan-subif-id'],
  assessmentId: 'vlan',
  references: [
    { title: 'IEEE 802.1Q: Bridges and Bridged Networks', url: 'https://standards.ieee.org/ieee/802.1Q/10323/' },
    { title: 'bridge(8): show / manipulate bridge addresses and devices', url: 'https://man7.org/linux/man-pages/man8/bridge.8.html' },
    { title: 'ifupdown2: VLAN-aware bridge mode', url: 'https://docs.nvidia.com/networking-ethernet-software/cumulus-linux-59/Layer-2/Ethernet-Bridging-VLANs/VLAN-aware-Bridge-Mode/' },
    { title: 'Debian wiki: NetworkConfiguration (VLANs)', url: 'https://wiki.debian.org/NetworkConfiguration#Howto_use_vlan_.28dot1q.2C_802.1q.2C_trunk.29_.28Etch.2C_Lenny.29' },
    { title: 'ip-link(8): VLAN type', url: 'https://man7.org/linux/man-pages/man8/ip-link.8.html' },
  ],
};
