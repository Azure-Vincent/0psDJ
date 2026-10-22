import type { Lesson } from '../types';

export const NETIF_LESSON: Lesson = {
  id: 'netif',
  moduleId: 'A',
  title: 'Network interfaces and virtual switches',
  level: 'intermediate',
  summary: 'What a network interface is to the Linux kernel: physical, loopback, VLAN, dummy, bridge, bond, veth and tun/tap devices; interface names (eth0 vs predictable names such as ens18 and enp1s0); administrative state, carrier and operstate; /sys/class/net; Linux bridges as switches (sw01); and the virtual switches of VMware, Hyper-V, KVM/Proxmox, VirtualBox and Docker.',
  concepts: ['net.interfaces', 'net.vlan', 'net.arp'],
  mode: 'simulated',

  what: `
A **network interface** is the kernel object that sends and receives frames: it has a **name** (eth0), an **index**, a **MAC address**, an **MTU**, flags and counters, and zero or more IP addresses. Every other topic in this module (addresses, routes, VLANs, DHCP, firewall rules with \`iifname\`/\`oifname\`) hangs off interfaces, so the first question in any network fault is: **does the interface exist, is it up, does it have a link, and is it attached where I think it is?**

Not every interface is a network card. The kernel has many interface **types**:

| Type | Example | What it is |
|---|---|---|
| Physical (or emulated) NIC | eth0, ens18, enp1s0 | A driver for real or virtual hardware (Intel e1000, virtio-net, vmxnet3, hv_netvsc). |
| Loopback | lo | Traffic to 127.0.0.0/8 and ::1 never leaves the host. Always present. |
| VLAN | eth3.30 | Adds/removes an 802.1Q tag on a parent interface (VLAN lesson). |
| Dummy | dummy0 | Always "up", drops everything sent to it: a stable home for service or loopback-style addresses. |
| Bridge | br0, vmbr0, virbr0, docker0 | A software **switch**: member ports, a MAC table, optionally VLAN filtering and STP. |
| Bond / team | bond0 | Two or more NICs acting as one (failover or LACP aggregation). |
| veth pair | veth3f2a@if7 | A virtual cable: what goes in one end comes out of the other. Connects containers to a bridge. |
| tun / tap | tun0, tap100i0 | Interfaces backed by a program: VPNs (tun, layer 3) and VM NICs (tap, layer 2). |
| WireGuard, GRE, VXLAN | wg0, gre1, vxlan100 | Tunnels: packets are encapsulated and sent over another interface. |

### Virtual switches
Every hypervisor contains a switch. A VM's virtual NIC is "cabled" to a port of that switch, and the switch has uplinks to physical NICs. Linux uses the **bridge** (KVM, Proxmox \`vmbr0\`, libvirt \`virbr0\`, Docker \`docker0\`) or **Open vSwitch**; VMware has the **vSphere Standard/Distributed Switch**; Hyper-V the **Hyper-V Virtual Switch**. They all behave like a physical switch: they learn MAC addresses, they can be VLAN-aware, and a VM attached to the wrong port group/VLAN is exactly as isolated as a server plugged into the wrong switch port.

### Why this is a troubleshooting topic
Interface problems look like "the server is down" from the outside, but the cause is local and often invisible from the network:
- The configuration names an interface that **does not exist** (renamed after a hypervisor migration, new NIC driver, cloned VM).
- The interface is **administratively down** (\`ip link set dev X down\`, \`auto\` missing in /etc/network/interfaces) or has **no carrier** (cable, switch port shut, virtual NIC "disconnected" in the hypervisor).
- A switch or bridge port is up but **not a member** of the bridge/VLAN, so frames go nowhere.

### In the lab
- **sw01** is a Linux **VLAN-aware bridge** (\`br0\`) with ports swp1–swp9: \`ip -br link\`, \`ip -d link show br0\`, \`bridge link\`, \`bridge vlan show\`, \`bridge fdb show\`. Its configuration is ifupdown2 (/etc/network/interfaces with \`bridge-ports\`, \`bridge-access\`, \`bridge-vids\`).
- **srv01, rtr01, ws01…** are Debian VMs with emulated Intel e1000 NICs (\`ethtool -i eth0\`). They keep the classic \`eth0\` names; \`ip link\` also shows the predictable name as \`altname enp1s0\`.
- Kernel state is readable under **/sys/class/net/** (operstate, carrier, address, mtu, speed, duplex, type, ifindex).
- You can create **dummy** interfaces (\`ip link add dummy0 type dummy\`) on any host.

> The simulator implements interface names and indexes, admin state (UP), carrier (LOWER_UP / NO-CARRIER), operstate, MAC and MTU, VLAN sub-interfaces, dummy interfaces, the sw01 bridge (membership, runtime \`ip link set PORT master br0\` / \`nomaster\`, VLAN filtering, MAC learning, \`master br0\`/\`bridge_slave\` details), /sys/class/net attributes, \`ethtool\`, and ifupdown failures for interfaces named in /etc/network/interfaces that do not exist. Not simulated on lab hosts: creating bridges, bonds, veth pairs or tun/tap devices (\`ip link add\` explains this), udev renaming rules and network namespaces. Those are taught here with real command output.
`,

  internals: `
### Anatomy of \`ip link\`
\`\`\`
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 52:54:00:c3:00:0a brd ff:ff:ff:ff:ff:ff
    altname enp1s0
\`\`\`
- **2:** the **ifindex**: a number the kernel assigns when the device is created. Routes, sockets and nftables refer to interfaces by index internally.
- **<…UP…>**: **administrative state**. The admin (or ifupdown/NetworkManager) said "up" with \`ip link set dev eth0 up\`.
- **LOWER_UP**: the driver reports **carrier**: a cable is connected and the other end is up (for a VM: the virtual NIC is connected to a vSwitch port). When admin-up without carrier, ip shows **NO-CARRIER** and \`state DOWN\`.
- **state UP / DOWN / UNKNOWN / LOWERLAYERDOWN**: the **operstate** (RFC 2863). UNKNOWN is normal for lo and dummy (no carrier concept). LOWERLAYERDOWN means "my parent is down" (a VLAN interface on a dead NIC).
- **master br0** (on bridge ports): this interface is a member of br0. Its frames are switched by the bridge, and it carries no IP address itself.

So there are **three independent questions**: does the interface exist (name), is it **admin up**, does it have **carrier**? \`ip -br link\` answers all three in one line per interface.

### /sys/class/net
Every interface is a directory in sysfs. Scripts and monitoring read it directly:
\`\`\`
/sys/class/net/eth0/operstate   up | down | unknown | lowerlayerdown | dormant
/sys/class/net/eth0/carrier     1 | 0      ("Invalid argument" when the interface is admin-down)
/sys/class/net/eth0/address     52:54:00:c3:00:0a
/sys/class/net/eth0/mtu         1500
/sys/class/net/eth0/speed       1000     (Mb/s; -1 or "Invalid argument" without link)
/sys/class/net/eth0/type        1 = Ethernet (ARPHRD_ETHER), 772 = loopback
/sys/class/net/eth0/master      symlink to the bridge or bond the interface belongs to
\`\`\`

### Where names come from
The kernel names NICs **eth0, eth1…** in the order drivers find them. That order is not guaranteed to be stable (two NICs, one driver loads faster: names swap), so **systemd-udevd renames** them at boot to **predictable names** derived from the hardware:

| Prefix | Meaning | Example |
|---|---|---|
| en / wl / ww | Ethernet / WLAN / WWAN | |
| o<n> | Onboard device index from firmware | eno1 |
| s<n> | PCI Express hot-plug **slot** number | ens18 (Proxmox virtio), ens192 (VMware vmxnet3), ens33 |
| p<b>s<s> | PCI **bus and slot** location | enp1s0, enp0s3 (VirtualBox), enp3s0f1 (function 1) |
| x<MAC> | Built from the MAC address (opt-in) | enx525400c3000a |

udev tries the policies in order (\`NamePolicy=\` in /usr/lib/systemd/network/99-default.link) and also records the other candidates as **alternative names** (\`altname enp1s0\`). The consequence for administrators: **the name depends on the virtual or physical hardware layout.** Moving a VM to another hypervisor, changing the NIC model (e1000 → virtio), adding a PCI card or updating firmware can change it. Configuration files that name interfaces (/etc/network/interfaces, netplan, nftables \`iifname\`, dhcpd/dhcrelay options, monitoring) then point at an interface that does not exist.

Ways to control names:
- Kernel parameter \`net.ifnames=0\` (often with \`biosdevname=0\`): keep the kernel's eth0/eth1 names (common in VM templates).
- A systemd **.link** file that matches the MAC address and sets a name:
  \`\`\`
  # /etc/systemd/network/10-lan0.link
  [Match]
  MACAddress=52:54:00:c3:00:0a
  [Link]
  Name=lan0
  \`\`\`
  Pick a name outside the kernel's ethN namespace (lan0, uplink0) so it cannot collide with a kernel-assigned name; run \`update-initramfs -u\` if the initramfs brings up the network.
- Tools that match by MAC instead of by name: netplan \`match: macaddress:\` with \`set-name:\`, NetworkManager profiles bound to a MAC.

### ifupdown and missing interfaces
At boot, \`networking.service\` runs \`ifup -a\` for every \`auto\` stanza (and \`allow-hotplug\` stanzas are brought up by udev when the device appears). If a stanza names a device that does not exist, ifup prints **Cannot find device "eth0"**, the unit ends **failed**, and the real NIC stays down: unconfigured, no address, no routes. From the network the host looks powered off.

### Linux bridges: a switch in the kernel
A bridge (\`ip link add br0 type bridge\`, or \`bridge-ports\` in /etc/network/interfaces) has **ports** (\`ip link set swp6 master br0\`). It behaves like a switch:
- **Learning**: it records source MAC → port in the forwarding database (\`bridge fdb show\`), entries age out after 300 s.
- **Forwarding**: known unicast to one port; broadcast and unknown unicast **flooded** to all ports in the VLAN.
- **VLAN filtering** (\`vlan_filtering 1\`, ifupdown2 \`bridge-vlan-aware yes\`): each port has a **PVID** (untagged frames belong to it) and a list of allowed VLANs (\`bridge vlan show\`). Access port = one VLAN, PVID, egress untagged; trunk = several VLANs, tagged.
- **STP** (\`stp_state 1\`): ports go through listening/learning before forwarding to avoid loops.
- The bridge device itself (br0) is the "switch's management interface": it can carry an IP address (that is how a KVM host keeps its own address once eth0 is a bridge port).

A port that is **not a member** of the bridge (missing from \`bridge-ports\`, removed with \`ip link set swp6 nomaster\`) still has carrier, so the LED is green and the server sees LOWER_UP, but the bridge never forwards its frames. ARP fails in both directions. \`bridge link\` lists only members; \`ip -d link show swp6\` without \`master br0\` / \`bridge_slave\` gives it away.

### Hypervisor virtual switches
| Platform | Switch | Attaching a VM | VLANs |
|---|---|---|---|
| VMware vSphere | vSphere Standard Switch (per host), Distributed Switch (vCenter) | VM NIC → **port group** | Port group VLAN ID (VST: 1–4094; 0 = untagged; 4095 = pass tags to the guest) |
| Hyper-V | Hyper-V Virtual Switch: **External** (bound to a NIC), **Internal** (host + VMs), **Private** (VMs only) | VM network adapter → switch | Per adapter: \`Set-VMNetworkAdapterVlan -Access -VlanId 20\` or -Trunk |
| KVM / Proxmox | Linux bridge (vmbr0) or Open vSwitch; VM NIC = a **tap** device that is a bridge port | VM NIC → bridge (+ VLAN tag) | Proxmox "VLAN aware" bridge + tag on the VM NIC |
| libvirt default | **virbr0**: a NAT network 192.168.122.0/24 with dnsmasq for DHCP | \`<interface type='network'><source network='default'/>\` | Not by default |
| VirtualBox | NAT, NAT Network, **Bridged** (to a host NIC), **Host-only**, Internal | Per VM adapter mode | Bridged passes tags from the guest |
| Docker | **docker0** bridge 172.17.0.0/16; each container gets a **veth pair** (one end in the container as eth0, the other on docker0) | \`docker network connect\` | User-defined networks = separate bridges |

Security settings matter on virtual switches too: VMware's **Promiscuous mode**, **MAC address changes** and **Forged transmits** (all Reject by default on Distributed Switches) block nested virtualization, bridges inside VMs and some clustering software until they are allowed on that port group.

### Bonding (link aggregation)
A **bond** combines NICs: \`mode active-backup\` (1) = one active, failover on carrier loss, needs nothing from the switch; \`mode 802.3ad\` (4) = **LACP**, both links active, the switch ports must be in a matching **port-channel / LAG**; balance-alb (6) and others exist for special cases. \`cat /proc/net/bonding/bond0\` shows the mode, the active slave and the MII status of each link. Hyper-V uses Switch Embedded Teaming (SET), VMware NIC teaming policies on the vSwitch.
`,

  deployment: [
    {
      id: 'linux-inspect',
      platform: 'Linux: inventory the interfaces',
      summary: 'Find out what exists, what is up, what has a link and what belongs to what. Steps marked "simulated" work in the sandbox.',
      prerequisites: ['A shell on the host (console if the network is down).'],
      steps: [
        { title: 'One line per interface', command: 'ip -br link\nip -br addr', what: 'Name, operstate, MAC and flags; then the addresses.', why: 'Answers "exists? admin up? carrier? address?" for every interface at once.', expected: 'lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP>\neth0             UP             52:54:00:c3:00:0a <BROADCAST,MULTICAST,UP,LOWER_UP>', simulated: true },
        { title: 'Details and alternative names', command: 'ip -d link show eth0', what: 'Flags, MTU, qdisc, master, bridge/VLAN details and altname lines.', why: '`-d` adds type-specific details: `vlan protocol 802.1Q id 30`, `bridge_slave state forwarding`.', expected: '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n    link/ether 52:54:00:c3:00:0a brd ff:ff:ff:ff:ff:ff\n    altname enp1s0', simulated: true },
        { title: 'Kernel attributes', command: 'ls /sys/class/net\ncat /sys/class/net/eth0/operstate /sys/class/net/eth0/carrier /sys/class/net/eth0/speed', what: 'The same state as files: easy to use in scripts and monitoring.', why: 'carrier 1 = link; operstate up = usable.', expected: 'eth0  lo\nup\n1\n1000', simulated: true },
        { title: 'Driver and link negotiation', command: 'ethtool -i eth0\nethtool eth0', what: 'Which driver/hardware the interface is, negotiated speed/duplex, "Link detected".', why: 'Identifies the NIC model (e1000, virtio_net, vmxnet3) and physical link problems (half duplex, 100 Mb/s on a gigabit port).', expected: 'driver: e1000\n...\n\tSpeed: 1000Mb/s\n\tDuplex: Full\n\tLink detected: yes', simulated: true },
        { title: 'Did the network configuration apply?', command: 'systemctl status networking\njournalctl -u networking -b', what: 'ifupdown\'s result for this boot.', why: '"Cannot find device" = a stanza names an interface that does not exist.', expected: '● networking.service - Raise network interfaces\n     Active: active (exited)', simulated: true },
      ],
    },
    {
      id: 'linux-dummy',
      platform: 'Linux: dummy interface for a service address',
      summary: 'Give a host an address that does not depend on a NIC (routing protocols, anycast DNS, a stable source address).',
      prerequisites: ['Root access.'],
      steps: [
        { title: 'Create and address it (runtime)', command: 'sudo ip link add dummy0 type dummy\nsudo ip addr add 192.0.2.1/32 dev dummy0\nsudo ip link set dummy0 up\nip addr show dummy0', what: 'A dummy device with a /32 host address.', why: 'A dummy interface never loses carrier, so the address stays usable whichever NIC is up.', expected: '3: dummy0: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN group default qlen 1000\n    link/ether be:ef:05:00:00:03 brd ff:ff:ff:ff:ff:ff\n    inet 192.0.2.1/32 scope global dummy0', simulated: true },
        { title: 'Make it persistent (ifupdown)', command: 'sudoedit /etc/network/interfaces\n\nauto dummy0\niface dummy0 inet static\n    address 192.0.2.1/32\n    pre-up ip link add dummy0 type dummy\n    post-down ip link del dummy0', what: 'ifupdown creates the device before configuring it.', why: 'systemd-networkd: a .netdev file with `Kind=dummy`; NetworkManager: `nmcli con add type dummy ifname dummy0`.', expected: '' },
        { title: 'Remove it', command: 'sudo ip link del dummy0', what: 'Deletes the device and its addresses.', why: 'Virtual devices can be deleted; physical NICs cannot.', expected: '', simulated: true },
      ],
    },
    {
      id: 'linux-bridge',
      platform: 'Linux bridge: a KVM host or a switch (sw01)',
      summary: 'Turn a NIC into a bridge port so VMs (or switch ports) share the same layer-2 network.',
      prerequisites: ['Console access: moving the host\'s address from eth0 to br0 interrupts remote sessions.', 'Package bridge-utils is not required with iproute2; ifupdown needs it for bridge_ports on Debian (ifupdown2 does not).'],
      steps: [
        { title: 'Runtime (iproute2)', command: 'ip link add br0 type bridge\nip link set eth0 master br0\nip link set br0 up\nip addr del 10.0.20.50/24 dev eth0\nip addr add 10.0.20.50/24 dev br0', what: 'Creates a bridge, enslaves the NIC and moves the host address onto the bridge.', why: 'A bridge port carries no IP address of its own: the address belongs on br0.', expected: '' },
        { title: 'Persistent (ifupdown2, as on sw01)', command: 'auto br0\niface br0\n    bridge-vlan-aware yes\n    bridge-ports swp1 swp2 swp3 swp4 swp5 swp6 swp7 swp8 swp9\n    bridge-vids 10 20 30\n    bridge-pvid 1\n    bridge-stp yes\n\nauto swp6\niface swp6\n    bridge-access 20', what: 'The bridge with its member list and per-port VLAN settings.', why: 'A port missing from bridge-ports is up but switched nowhere. `ifreload -a` applies changes without a reboot.', expected: '' },
        { title: 'Verify membership and VLANs', command: 'bridge link\nbridge vlan show\nbridge fdb show br0', what: 'Members and their STP state, VLANs per port, learned MACs.', why: 'Every connected access port should appear in all three: member, one PVID VLAN, at least one learned MAC.', expected: '7: swp6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 master br0 state forwarding priority 32 cost 100\nswp6              20 PVID Egress Untagged', simulated: true },
        { title: 'Bridge details', command: 'ip -d link show br0', what: 'vlan_filtering, stp_state, ageing_time, bridge_id.', why: 'vlan_filtering 0 on a bridge that should separate VLANs merges them into one broadcast domain.', expected: 'bridge forward_delay 1500 hello_time 200 max_age 2000 ageing_time 30000 stp_state 1 priority 32768 vlan_filtering 1 vlan_protocol 802.1Q', simulated: true },
      ],
    },
    {
      id: 'linux-names',
      platform: 'Linux: stable interface names',
      summary: 'Survive hardware and hypervisor changes without editing every configuration file.',
      prerequisites: ['Know the MAC address of each NIC (ip link).'],
      steps: [
        { title: 'See what udev would call it', command: 'udevadm test-builtin net_id /sys/class/net/eth0 2>/dev/null\nip link show eth0 | grep altname', what: 'The predictable name candidates (ID_NET_NAME_SLOT, ID_NET_NAME_PATH…).', why: 'Shows the name the interface gets if eth naming is disabled or the hardware changes.', expected: 'ID_NET_NAME_MAC=enx525400c3000a\nID_NET_NAME_PATH=enp1s0' },
        { title: 'Pin a name by MAC (systemd .link)', command: 'cat > /etc/systemd/network/10-lan0.link <<EOF\n[Match]\nMACAddress=52:54:00:c3:00:0a\n[Link]\nName=lan0\nEOF\nupdate-initramfs -u', what: 'udev names the NIC with this MAC lan0 on every boot.', why: 'Names follow the NIC, not the PCI slot. Remember to update the MAC when the virtual NIC is replaced.', expected: '' },
        { title: 'After a migration or NIC change', command: 'ip -br link\ngrep -rn "eth0" /etc/network/interfaces /etc/nftables.conf /etc/default/ 2>/dev/null', what: 'Compare the names that exist with the names configured.', why: 'Every file that names the old interface must follow (network config, firewall iifname/oifname, DHCP server/relay interfaces, monitoring).', expected: '' },
      ],
    },
    {
      id: 'hypervisors',
      platform: 'VMware, Hyper-V, Proxmox, Docker',
      summary: 'Where the "switch port" of a VM or container is configured.',
      prerequisites: [],
      steps: [
        { title: 'VMware vSphere (PowerCLI)', command: 'Get-VirtualPortGroup -VMHost esx01 | Select Name, VLanId, VirtualSwitch\nGet-VM srv01 | Get-NetworkAdapter | Select Name, NetworkName, ConnectionState, MacAddress', what: 'Port groups with their VLAN IDs, and which port group the VM\'s NIC uses and whether it is connected.', why: '"Connected" unchecked in the VM settings = no carrier in the guest (NO-CARRIER).', expected: 'Name     NetworkName  ConnectionState\nNetwork adapter 1  VLAN20-Servers  Connected, GuestControl, StartConnected' },
        { title: 'Hyper-V', command: 'Get-VMSwitch | Select Name, SwitchType, NetAdapterInterfaceDescription\nGet-VMNetworkAdapter -VMName srv01 | Select SwitchName, MacAddress, Status\nGet-VMNetworkAdapterVlan -VMName srv01', what: 'Switch types, the VM\'s switch and its VLAN mode.', why: 'A VM on an Internal or Private switch cannot reach the physical network.', expected: 'VMName OperationMode AccessVlanId\nsrv01  Access        20' },
        { title: 'Proxmox / KVM', command: 'cat /etc/network/interfaces   # vmbr0 with bridge-ports eno1, bridge-vlan-aware yes\nqm config 101 | grep ^net\nbridge link', what: 'The host bridge, the VM NIC (model, MAC, bridge, VLAN tag) and the tap ports on the bridge.', why: 'net0: virtio=…,bridge=vmbr0,tag=20 → the guest NIC is virtio (ens18 in Debian) in VLAN 20.', expected: 'net0: virtio=BC:24:11:3A:5E:01,bridge=vmbr0,tag=20' },
        { title: 'Docker', command: 'ip -br link | grep -E "docker0|veth"\ndocker network inspect bridge --format "{{range .Containers}}{{.Name}} {{.IPv4Address}}{{end}}"', what: 'The docker0 bridge, one veth per container, and container addresses.', why: 'The veth peer index (veth…@ifN) pairs the host end with eth0 inside the container.', expected: 'docker0          UP             02:42:5c:1e:9a:10 <BROADCAST,MULTICAST,UP,LOWER_UP>\nveth3f2a1b9@if7  UP             5e:21:0c:44:9b:2e <BROADCAST,MULTICAST,UP,LOWER_UP>' },
      ],
    },
  ],

  configIntro: `
Interfaces are configured by exactly **one** network stack per host. Find out which before editing anything: ifupdown (/etc/network/interfaces, Debian servers and the lab), netplan (Ubuntu), NetworkManager (desktops, RHEL), systemd-networkd. Two stacks managing the same NIC fight each other.
`,

  configFiles: [
    {
      platform: 'Linux',
      items: [
        { path: '/etc/network/interfaces (+ interfaces.d/)', purpose: 'ifupdown/ifupdown2: auto/allow-hotplug, iface stanzas, bridge-*, bond-*, vlan-raw-device, mtu, hwaddress.' },
        { path: '/etc/systemd/network/*.link', purpose: 'udev naming and link settings by MAC/path (Name=, MACAddress=, MTUBytes=).' },
        { path: '/etc/systemd/network/*.netdev, *.network', purpose: 'systemd-networkd virtual devices (bridge, bond, dummy, vlan) and their configuration.' },
        { path: '/etc/netplan/*.yaml', purpose: 'Ubuntu: ethernets, bridges, bonds, vlans with match/set-name.' },
        { path: '/etc/NetworkManager/system-connections/', purpose: 'NetworkManager profiles (interface-name= or mac-address=).' },
        { path: '/etc/default/grub (GRUB_CMDLINE_LINUX="net.ifnames=0")', purpose: 'Disable predictable names (run update-grub).' },
        { path: '/sys/class/net/<if>/, /proc/net/bonding/<bond>', purpose: 'Runtime state: operstate, carrier, master; bond mode and slave status.' },
      ],
    },
    {
      platform: 'Hypervisors',
      items: [
        { path: 'VMware: vSwitch / port group settings (vCenter)', purpose: 'VLAN ID, teaming, security policy (promiscuous, MAC changes, forged transmits).' },
        { path: 'Hyper-V: Get-VMSwitch / Set-VMNetworkAdapterVlan', purpose: 'Switch type and per-adapter VLAN.' },
        { path: 'Proxmox: /etc/network/interfaces (vmbrN), /etc/pve/qemu-server/<id>.conf (netN)', purpose: 'Host bridges and VM NIC model, MAC, bridge, tag.' },
        { path: 'libvirt: virsh net-dumpxml default, domain XML <interface>', purpose: 'NAT network virbr0 or bridge attachment.' },
      ],
    },
  ],

  directives: [
    { name: 'auto IFACE / allow-hotplug IFACE', compiledDefault: 'neither (interface stays down)', recommended: 'auto for servers', explanation: '`auto`: brought up by `ifup -a` at boot. `allow-hotplug`: brought up when udev reports the device (Debian installer default).', security: 'An interface without either stays down after reboot: a classic "worked until the reboot" fault.' },
    { name: 'iface IFACE inet static|dhcp|manual', compiledDefault: '—', recommended: 'manual for bridge/bond members', explanation: 'How the interface gets its address. Bridge and bond members carry no address.', security: 'Must name an interface that exists; otherwise ifup fails with "Cannot find device".' },
    { name: 'bridge-ports (bridge_ports)', compiledDefault: 'none', recommended: 'List every member explicitly', explanation: 'Members of the bridge. ifupdown2 also accepts globs/ranges (swp1-9 via `glob`).', security: 'A port missing here is up but isolated; an extra port can join an untrusted segment to the bridge.' },
    { name: 'bridge-vlan-aware yes / bridge-vids / bridge-pvid / bridge-access', compiledDefault: 'no (one flat broadcast domain)', recommended: 'yes on multi-VLAN bridges', explanation: 'VLAN filtering; allowed VLANs per port; untagged VLAN; access port shortcut.', security: 'Without VLAN awareness all VLANs share one broadcast domain.' },
    { name: 'bridge-stp', compiledDefault: 'off', recommended: 'on when the bridge has more than one uplink', explanation: 'Spanning Tree on the bridge.', security: 'A loop without STP floods broadcast traffic until the network stops (broadcast storm).' },
    { name: 'bond-slaves / bond-mode / bond-miimon', compiledDefault: 'balance-rr, miimon 0', recommended: 'active-backup or 802.3ad, miimon 100', explanation: 'Bond members, mode and link monitoring interval (ms).', security: '802.3ad without a matching LACP port-channel on the switch drops traffic or loops.' },
    { name: 'net.ifnames=0 (kernel command line)', compiledDefault: 'predictable names on', recommended: 'Prefer .link files with MAC matching', explanation: 'Keeps eth0/eth1 kernel names.', security: 'Kernel names are not guaranteed stable on hosts with several NICs.' },
    { name: '[Match] MACAddress= / [Link] Name= (.link)', compiledDefault: '99-default.link NamePolicy', recommended: 'For servers whose names must not change', explanation: 'Names a NIC after its MAC address.', security: 'Use names outside ethN to avoid collisions with kernel names.' },
  ],

  troubleshootingIntro: `
### Work bottom-up, on both ends
1. **Does it exist?** \`ip -br link\`. The name in the configuration must be in this list (eth0 vs ens18 after a migration).
2. **Admin up?** \`UP\` in the flags. If not: \`auto\` missing, ifup failed (\`systemctl status networking\`), or someone ran \`ip link set … down\`.
3. **Carrier?** \`LOWER_UP\` / \`cat /sys/class/net/X/carrier\`. NO-CARRIER: cable, switch port disabled, VM NIC "disconnected" in the hypervisor, wrong vSwitch uplink.
4. **Address and routes?** \`ip -br addr\`, \`ip route\`.
5. **Can it reach its neighbour?** \`ping\` the gateway, then \`ip neigh\`: **FAILED** with carrier on both sides means layer 2 between them is broken: wrong VLAN, port not in the bridge, wrong port group.
6. **On the switch / bridge**: \`bridge link\` (member?), \`bridge vlan show\` (right VLAN?), \`bridge fdb show\` (did it learn the server's MAC on that port?).
`,

  errorMap: [
    { message: 'Cannot find device "eth0"', layer: 'Interface', meaning: 'The configuration names an interface that does not exist (renamed, removed, typo).', firstCheck: 'ip -br link; compare with /etc/network/interfaces' },
    { message: 'ifup: failed to bring up eth0', layer: 'Interface', meaning: 'ifupdown could not configure the stanza; networking.service fails.', firstCheck: 'journalctl -u networking -b' },
    { message: '<NO-CARRIER,BROADCAST,MULTICAST,UP> … state DOWN', layer: 'Physical / virtual link', meaning: 'Admin up, but no link: cable, switch port, or disconnected virtual NIC.', firstCheck: 'ethtool IF (Link detected); switch port / hypervisor NIC settings' },
    { message: 'state DOWN, no UP flag', layer: 'Interface', meaning: 'Administratively down: never brought up.', firstCheck: 'auto stanza; systemctl status networking' },
    { message: 'state LOWERLAYERDOWN', layer: 'Interface', meaning: 'A stacked interface (VLAN, bond member\'s master) whose parent is down.', firstCheck: 'ip link show PARENT' },
    { message: 'cat: /sys/class/net/eth0/carrier: Invalid argument', layer: 'Interface', meaning: 'The interface is admin-down; the kernel reports no carrier state.', firstCheck: 'ip link set dev eth0 up (or fix the configuration)' },
    { message: '10.0.20.10 dev eth1 FAILED (ip neigh)', layer: 'Layer 2', meaning: 'ARP got no answer: the target is down, unaddressed, or not on the same layer-2 segment.', firstCheck: 'Target ip -br addr; switch bridge link / bridge vlan show' },
    { message: 'Device "br9" does not exist. / Cannot find device "br9"', layer: 'Interface', meaning: 'iproute2 was given a name that does not exist (ip link show / ip link set).', firstCheck: 'ip -br link' },
  ],

  scenarioIds: ['netif-renamed-nic', 'netif-bridge-port'],
  assessmentId: 'netif',
  references: [
    { title: 'systemd.net-naming-scheme(7): predictable interface names', url: 'https://www.freedesktop.org/software/systemd/man/latest/systemd.net-naming-scheme.html' },
    { title: 'systemd.link(5)', url: 'https://www.freedesktop.org/software/systemd/man/latest/systemd.link.html' },
    { title: 'Debian Wiki: NetworkInterfaceNames', url: 'https://wiki.debian.org/NetworkInterfaceNames' },
    { title: 'interfaces(5) (ifupdown)', url: 'https://manpages.debian.org/bookworm/ifupdown/interfaces.5.en.html' },
    { title: 'ip-link(8)', url: 'https://manpages.debian.org/bookworm/iproute2/ip-link.8.en.html' },
    { title: 'bridge(8)', url: 'https://manpages.debian.org/bookworm/iproute2/bridge.8.en.html' },
    { title: 'Linux kernel: sysfs-class-net ABI (operstate, carrier)', url: 'https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net' },
    { title: 'Linux kernel: bonding driver documentation', url: 'https://www.kernel.org/doc/Documentation/networking/bonding.rst' },
    { title: 'RFC 2863: The Interfaces Group MIB (operstatus)', url: 'https://www.rfc-editor.org/rfc/rfc2863' },
    { title: 'VMware vSphere Networking documentation', url: 'https://docs.vmware.com/en/VMware-vSphere/index.html' },
    { title: 'Microsoft: Hyper-V virtual switch', url: 'https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v-virtual-switch/hyper-v-virtual-switch' },
    { title: 'Proxmox VE: Network configuration', url: 'https://pve.proxmox.com/wiki/Network_Configuration' },
  ],
};
