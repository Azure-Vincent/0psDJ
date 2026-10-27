import type { Lesson } from '../types';

export const VLAN_LESSON: Lesson = {
  id: 'vlan',
  moduleId: 'A',
  title: 'VLANs, trunks and inter-VLAN routing',
  level: 'intermediate',
  summary: 'How one switch carries several separate broadcast domains: access and trunk ports, 802.1Q tags, the PVID/native VLAN, MAC learning per VLAN, and routing between VLANs with router-on-a-stick sub-interfaces.',
  concepts: ['net.vlan', 'net.arp', 'net.routing'],

  what: `
A **switch** connects the computers of a local network. Normally, every port on a switch belongs to the same network: a broadcast sent by one computer, such as an ARP request ("who has 10.0.10.1?"), reaches every other port. All the devices a broadcast can reach together form one **broadcast domain**.

A **VLAN** (virtual LAN) splits one physical switch into several separate broadcast domains. Computers in VLAN 10 and VLAN 20 can be plugged into the same switch, yet an ARP broadcast from VLAN 10 never reaches VLAN 20. At layer 2 they behave like two separate switches. To get from one VLAN to another, traffic has to be **routed**, by a router or a layer-3 switch, exactly like traffic between any two networks in the [IP networking lesson](#/lesson/ipnet/what). That router is also the natural place to put firewall rules between the VLANs.

Think of an office building with one big open floor. VLANs are like putting up glass walls: everyone still sits on the same floor (the same switch), but each team only hears its own conversations, and to talk to another team you have to go through a door (the router).

### Why VLANs are used
- **Separation and security**: servers, office PCs, guests, phones and management interfaces each get their own VLAN and subnet, with firewall rules controlling what may pass between them.
- **Smaller broadcast domains**: less broadcast noise (ARP, DHCP), and a problem in one VLAN, such as a broadcast storm, stays in that VLAN.
- **Flexibility**: which VLAN a port belongs to is configuration, not cabling. Moving a desk to another department means changing one port setting.

:::practice
Q: A guest Wi-Fi and the office PCs share the same switches. How do VLANs keep guests away from office servers?
A: Guests get their own VLAN and subnet. Their broadcasts never reach the office VLAN, and anything between the two must pass the **router or firewall**, where rules can block it.
Q: A broadcast storm starts in VLAN 40. Which other VLANs on the same switch are flooded?
A: **None.** A broadcast stays inside its own VLAN.
:::

### Two kinds of switch ports
- **Access port**: belongs to one VLAN. Frames go in and out **untagged** (unchanged), so the connected computer does not need to know VLANs exist. Used for PCs, printers and most servers.
- **Trunk port**: carries several VLANs over one cable. Each frame carries an **802.1Q tag**, a small label with the VLAN number, so the device at the other end can tell the VLANs apart. Used between switches, and towards routers or hypervisors that serve several VLANs. One VLAN per trunk may travel **untagged**; it is called the *native VLAN* (or PVID on Linux).

:::practice
Q: Which port type do you use for a desktop PC, and which for the link to a hypervisor that runs VMs in VLANs 10, 20 and 30?
A: The PC: an **access port** (one VLAN, untagged). The hypervisor: a **trunk** carrying VLANs 10, 20 and 30 tagged.
Q: A frame for the native VLAN travels over a trunk. Does it carry an 802.1Q tag?
A: **No.** The native VLAN (PVID) travels untagged; all other VLANs on the trunk are tagged.
:::

### In the lab
**sw01** is a Debian machine acting as a switch, using a **VLAN-aware Linux bridge** called br0, configured with ifupdown2 (the same way as Cumulus Linux or Debian). It has three VLANs: VLAN 10 for the office (ws01, ws02, ns1), VLAN 20 for servers (srv01) and VLAN 30 for development (dev01). rtr01 connects to VLANs 10 and 20 through two access ports, and to VLAN 30 through a **trunk** (its port eth3, tagged with VLAN 30), using the sub-interface **eth3.30**. A router serving VLANs over a trunk like this is called *router-on-a-stick*.

> What the simulator models: access and trunk ports (bridge-access, bridge-vids, bridge-pvid), untagged and tagged membership, VLAN sub-interfaces on hosts (eth3.30, \`ip link add … type vlan\`), MAC learning per VLAN (bridge fdb), 802.1Q tags in \`tcpdump -e\` and in PCAP export, and the difference between runtime and saved switch configuration. Spanning tree, Q-in-Q, LACP and VLAN-unaware bridges are not modelled, and membership is treated as symmetric.
`,

  internals: `
### The 802.1Q tag
To mark which VLAN a frame belongs to, the switch inserts 4 extra bytes into the Ethernet frame, right after the source MAC address. This is the **802.1Q tag**:

\`\`\`
| dst MAC (6) | src MAC (6) | 0x8100 (TPID) | PCP(3) DEI(1) VID(12) | EtherType (e.g. 0x0800) | payload ... |
\`\`\`
- **TPID 0x8100** marks the frame as tagged.
- **VID** (12 bits): VLAN 1–4094 (0 and 4095 reserved).
- **PCP**: priority for QoS (voice), **DEI**: drop eligibility.
Because the tag adds 4 bytes, trunk ports must accept frames of up to 1522 bytes instead of the usual 1518.

:::practice
Q: A normal Ethernet frame can be up to 1518 bytes. How large can a tagged frame on a trunk be, and why?
A: **1522 bytes**: the 802.1Q tag adds 4 bytes.
Q: Which VLAN numbers can you use for real VLANs, and why not 4095?
A: **1 to 4094**. The VLAN ID has 12 bits (0–4095), and 0 and 4095 are reserved.
:::

### What the switch does with each frame (VLAN-aware Linux bridge)
Follow a frame through the switch in three stages: when it arrives (ingress), when the switch decides where to send it (forwarding), and when it leaves (egress).
**Ingress** (frame arrives on a port):
1. Untagged frame → assigned to the port's **PVID**. A port without a PVID drops untagged frames.
2. Tagged frame → kept in its VLAN **if the port is a member of that VLAN**, otherwise dropped (ingress filtering).

**Forwarding**: the bridge looks up the destination MAC **in the forwarding database of that VLAN** (learned from source MACs, per VLAN). Unknown unicast, broadcast and multicast are **flooded to every port that is a member of the VLAN**, never to other VLANs.

**Egress**: the frame leaves **untagged** on ports where the VLAN is marked *untagged* (access ports, the native VLAN of a trunk), **tagged** everywhere else.

:::practice
Q: An untagged frame arrives on a port with PVID 20. A tagged frame for VLAN 40 arrives on the same port, which is not a member of VLAN 40. What happens to each?
A: The untagged frame is placed in **VLAN 20**. The tagged frame is **dropped** by ingress filtering, because the port is not a member of VLAN 40.
Q: A PC in VLAN 10 sends a broadcast. Does a PC in VLAN 20 on the same switch receive it?
A: **No.** Broadcasts are flooded only to ports that are members of VLAN 10. Reaching VLAN 20 always needs a router.
:::

### Linux bridge vocabulary (ifupdown2)
| Setting | Meaning |
|---|---|
| \`bridge-vlan-aware yes\` | enable VLAN filtering on the bridge |
| \`bridge-access 10\` | access port: VLAN 10, PVID 10, untagged |
| \`bridge-vids 10 20 30\` | VLANs a port carries tagged (on the bridge: default for ports) |
| \`bridge-pvid 1\` | VLAN for untagged frames, sent untagged (native VLAN) |
| \`bridge vlan show\` / \`bridge fdb show\` | runtime membership / learned MAC addresses per VLAN |
On Cisco IOS the same ideas are \`switchport mode access\` + \`switchport access vlan 10\`, and \`switchport mode trunk\` + \`switchport trunk allowed vlan 30\` + \`switchport trunk native vlan 1\`.

:::practice
Q: A switch port is configured with \`bridge-vids 20 30\` and \`bridge-pvid 1\`. Describe what travels over it.
A: It is a **trunk**: VLANs 20 and 30 travel **tagged**, and VLAN 1 travels untagged (the native VLAN).
Q: Which command shows the VLANs that each switch port is a member of right now, and which shows the MAC addresses learned per VLAN?
A: \`bridge vlan show\` for membership; \`bridge fdb show\` for the learned MAC addresses.
:::

### Hosts on trunks: VLAN sub-interfaces
A Linux host connected to a trunk (a router or a hypervisor) receives tagged frames on its physical network card, and hands each VLAN to its own virtual interface, a **sub-interface**. To the rest of the system, each sub-interface looks like a separate network card in that VLAN. For example, \`eth3.30\` = VLAN 30 on eth3 (\`ip link add link eth3 name eth3.30 type vlan id 30\`, or an \`iface eth3.30\` stanza; Debian derives the VLAN ID from the name). Untagged frames on the trunk go to eth3 itself.

:::practice
Q: A hypervisor has a trunk on eth1. What does an interface named \`eth1.50\` handle?
A: Frames tagged with **VLAN 50** on eth1: the sub-interface removes the tag on the way in and adds it on the way out, so it behaves like a separate network card in VLAN 50.
Q: Where do **untagged** frames that arrive on that trunk go?
A: To **eth1** itself, not to any sub-interface.
:::

### Router-on-a-stick
rtr01 has one sub-interface per VLAN on the trunk, each with an address that serves as that VLAN's **default gateway** (10.0.30.1 on eth3.30). Here is the path of a packet from dev01 (VLAN 30) to srv01 (VLAN 20): dev01 → switch (untagged in, tagged 30 out on swp7) → rtr01 eth3.30 → routing decision, TTL−1, forward filter → eth1 (VLAN 20) → srv01. Between VLANs the rules of routing apply: different subnets, gateways, firewall.

:::practice
Q: A router has sub-interfaces eth3.10 (10.0.10.1/24) and eth3.20 (10.0.20.1/24) on one trunk. What default gateway should hosts in VLAN 20 use?
A: **10.0.20.1**, the router's address on that VLAN's sub-interface.
Q: A packet from VLAN 10 to VLAN 20 crosses the trunk twice. Why is it still routed, not just switched?
A: The two VLANs are different subnets, so the host sends the packet to its gateway; the router lowers the TTL, applies its forward filter and sends it back out on the other sub-interface. The trunk is just the cable both VLANs share.
:::

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
The switch configuration decides which broadcast domain every port belongs to: get one port wrong and the computer behind it is effectively on a different network. The VLAN explorer below lets you edit a copy of sw01's port table. It recomputes the broadcast domains with the simulator's own layer-2 code and shows the ifupdown2 stanza you would write for each port.
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
### Check layer 2 first, then routing
A VLAN problem usually looks like this: the cable is plugged in, the link is up, the computer has the right address, and yet nothing works. That is because the computer is effectively on the wrong network. So check layer 2 (which VLAN is this port really in?) before you look at routing.

1. **Is the gateway in my broadcast domain?** Ping the gateway and look at \`ip neigh\`. FAILED means nobody answered the ARP (or, for IPv6, NDP) request: either the VLAN is wrong or the gateway itself is down.
2. **Which VLAN is the host really in?** On the switch, \`bridge fdb show\` shows which VLAN the host's MAC address was learned in, and \`bridge vlan show\` shows the port's PVID. Compare both with the network plan.
3. **Is the VLAN carried towards the router?** Check the trunk port with \`bridge vlan show\` on the switch, and run \`tcpdump -e -n -i eth3\` on the router. \`-e\` prints the Ethernet header, including the VLAN tag. Do tagged frames go out, and does anything come in?
4. **Does the router tag with the right VLAN number?** \`ip -d link show\` on the router should say "vlan protocol 802.1Q id 30" for eth3.30.
5. **Is the fix saved?** Compare \`bridge vlan show\` (what runs now) with /etc/network/interfaces (what is saved). \`ifreload -a\` or a reboot applies the file, so make sure the file is right.

:::practice
Q: A PC's \`ip neigh\` shows its gateway FAILED. On the switch, \`bridge fdb show\` lists the PC's MAC in VLAN 20, but the plan says VLAN 10. What is the fix?
A: Move the PC's **switch port** to VLAN 10 (bridge-access 10), apply it, and save it in /etc/network/interfaces. The PC's IP configuration is fine.
Q: Which tcpdump option shows the VLAN tag of each frame on a trunk?
A: \`-e\` (print the Ethernet header): for example \`tcpdump -e -n -i eth3\`.
:::

### Typical mistakes
- **Access port in the wrong VLAN**: the link is up and the host is configured correctly, but nobody answers its ARP request for the gateway. The host may even get an address from another VLAN's DHCP server.
- **VLAN missing from a trunk** (sometimes called "pruned"): a whole VLAN loses its gateway, while the hosts inside it can still talk to each other.
- **Native VLAN mismatch**: the two ends of a trunk disagree about which VLAN travels untagged, so traffic leaks into the wrong VLAN or disappears.
- **Wrong sub-interface ID**: the router tags with VLAN 3 instead of 30. Everything looks fine on the router itself, which makes this one hard to spot.
- **Forgetting runtime versus saved configuration**: \`bridge vlan add\` fixes it now, but only the file survives a reboot.

:::practice
Q: All hosts in VLAN 50 can ping each other, but none can reach their gateway. Other VLANs are fine. Which mistake fits?
A: **VLAN 50 is missing from the trunk** towards the router (or the router's sub-interface uses the wrong VLAN ID).
Q: You fixed a port's VLAN with \`bridge vlan add\`. What happens at the next reboot if you did nothing else?
A: The fix is **lost**: only /etc/network/interfaces survives a reboot.
:::

### Keeping VLANs secure
VLANs separate broadcast domains. They are not a firewall on their own. Good practice:
- **Allow only the VLANs that are needed on each trunk.** A trunk that carries every VLAN lets a mistake (or an attacker) on one switch reach all of them.
- **Make end-user ports access ports, never trunks.** A trunk on a desk port lets the connected device send into any VLAN by tagging its frames. "Every port a trunk, so moves need no reconfiguration" is convenient and unsafe.
- **Use an unused VLAN as the native VLAN, or tag every VLAN on trunks.** Untagged traffic on a trunk belongs to the native VLAN; if that is VLAN 1 and also used by hosts, a "double-tagged" frame can hop into another VLAN.
- **Filter traffic between VLANs where it is routed** (on the router or firewall). Routing is what connects VLANs, so that is where the policy belongs.

:::practice
Q: Why is putting every switch port into trunk mode, so that desk moves need no reconfiguration, a security problem?
A: A device on a trunk port can **tag its own frames** and send into any VLAN the trunk carries, bypassing the router's filtering.
Q: Where should the rules that control traffic between the server VLAN and the office VLAN live?
A: On the **router or firewall** that routes between them.
:::

`,

  errorMap: [
    { message: 'Destination Host Unreachable (from the host itself) for its own gateway', layer: 'Layer 2 / VLAN', meaning: 'ARP for the gateway got no reply: wrong VLAN on the access port, VLAN not on the trunk, or wrong sub-interface ID.', firstCheck: 'bridge fdb show / bridge vlan show on the switch' },
    { message: 'Host gets an address from the wrong subnet via DHCP', layer: 'Layer 2 / VLAN', meaning: 'Its switch port is in another VLAN, and that VLAN\'s DHCP server answered.', firstCheck: 'The port\'s PVID on the switch' },
    { message: 'Hosts in one VLAN reach each other but not the gateway', layer: 'Trunk', meaning: 'The VLAN is not carried (or wrongly tagged) towards the router.', firstCheck: 'bridge vlan show on the trunk port; ip -d link on the router' },
    { message: 'Link up, interface UP, address correct, nothing works', layer: 'Layer 2', meaning: 'The physical connection is fine, but the port is in the wrong VLAN, so the host is effectively on a different network.', firstCheck: 'tcpdump on the host: do broadcasts from expected neighbours arrive?' },
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
