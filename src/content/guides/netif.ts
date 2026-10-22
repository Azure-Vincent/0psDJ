// Operate & recover guide: network interfaces, names, link state, Linux bridges
// and hypervisor virtual switches.

import type { ServiceGuide } from '../types';

export const NETIF_GUIDE: ServiceGuide = {
  purpose:
    'A **network interface** is where the operating system meets the network: a named kernel device with a MAC address, an MTU, an administrative state and a carrier state. Physical NICs, VLAN sub-interfaces, bridges, bonds, veth pairs and tunnels are all interfaces. **Virtual switches** (Linux bridges, Open vSwitch, VMware vSwitches, the Hyper-V Virtual Switch, docker0) connect the interfaces of VMs and containers the way a physical switch connects servers. Most "server unreachable" incidents that are not routing or firewall problems are one of three interface questions: wrong name, not up, or not attached to the right switch port/VLAN.',
  architecture: [
    { q: 'What does it accomplish?', a: 'Gives the IP stack somewhere to send packets, and gives VMs/containers a port on a (virtual) switch.' },
    { q: 'How does it work internally?', a: 'Drivers register net devices with the kernel (ifindex, name, MAC). udev renames NICs to predictable names at boot. The network stack (ifupdown, netplan/networkd, NetworkManager) brings them up and adds addresses. A bridge is a kernel device with member ports: it learns MACs, floods unknown traffic, filters VLANs and runs STP.' },
    { q: 'Which protocols does it use?', a: 'Ethernet (IEEE 802.3), 802.1Q VLAN tags, 802.1D/802.1w STP, 802.1AX/802.3ad LACP for bonds; ARP/NDP on top.' },
    { q: 'Which ports and transport?', a: 'None: layer 1 and 2. Firewall rules refer to interfaces by name (iifname/oifname), which is why names matter beyond the network configuration.' },
    { q: 'Which processes and OS components implement it?', a: 'Kernel drivers (e1000, virtio_net, vmxnet3, hv_netvsc), the bridge/bonding/8021q modules, systemd-udevd (naming), networking.service (ifupdown) or systemd-networkd/NetworkManager. On hypervisors: the vSwitch in the VMkernel (ESXi), the Hyper-V extensible switch, Linux bridges/OVS (KVM, Proxmox), dockerd (docker0, veth).' },
    { q: 'Which other services does it depend on?', a: 'The hypervisor\'s virtual NIC and switch configuration (connected, port group, VLAN), physical cabling and switch ports, and a configuration that names interfaces that actually exist.' },
    { q: 'How do requests travel?', a: 'srv01 eth0 → cable → sw01 swp6 (bridge port, VLAN 20 access) → br0 forwards by MAC/VLAN → swp5 → rtr01 eth1. In a hypervisor: guest NIC → tap/vNIC port → vSwitch → uplink NIC → physical switch.' },
    { q: 'How do authentication and authorisation work?', a: 'Changing interfaces needs CAP_NET_ADMIN (root). On vSwitches, security policies (promiscuous mode, MAC changes, forged transmits) decide what a VM may send and receive; on physical switches, port security and 802.1X.' },
    { q: 'How does it start at boot?', a: 'Drivers load → udev names the NICs → networking.service (ifup -a for auto stanzas) or networkd/NM configures them; bridges and bonds are created before their members are enslaved. Hypervisors connect VM NICs to the vSwitch when the VM powers on (if "connect at power on" is set).' },
    { q: 'What happens if it terminates unexpectedly?', a: 'If networking.service fails, interfaces stay unconfigured until fixed; existing ones keep their state. If a bridge is deleted, all its ports lose connectivity at once. If a bond loses its last link, the bond goes NO-CARRIER.' },
  ],
  ports: [
    { port: 'Ethernet', proto: 'L2', purpose: 'Frames between interfaces on the same segment/VLAN' },
    { port: '802.1Q tag', proto: 'L2', purpose: 'VLAN membership on trunks (bridge vlan show, port group VLAN ID)' },
    { port: 'STP BPDUs (01:80:c2:00:00:00)', proto: 'L2', purpose: 'Loop prevention on bridges with bridge-stp yes' },
    { port: 'LACPDUs (01:80:c2:00:00:02)', proto: 'L2', purpose: 'Link aggregation negotiation for 802.3ad bonds' },
  ],
  processes: [
    { name: 'kernel drivers and net devices', platform: 'Linux', role: 'NIC, bridge, bond, VLAN, dummy, veth, tun/tap devices' },
    { name: 'systemd-udevd', platform: 'Linux', role: 'Predictable names and .link files at device discovery' },
    { name: 'networking.service (ifupdown / ifupdown2)', platform: 'Debian (the lab)', role: 'ifup -a for /etc/network/interfaces at boot; ifreload -a applies changes' },
    { name: 'systemd-networkd / NetworkManager', platform: 'Ubuntu, RHEL, desktops', role: 'Alternative network stacks (only one may manage an interface)' },
    { name: 'ESXi vSwitch / Hyper-V Virtual Switch / OVS', platform: 'Hypervisors', role: 'Virtual switching between VM NICs and uplinks' },
  ],
  dependencies: {
    title: 'What srv01 needs to be reachable at layer 2',
    rows: [
      { label: 'Host', nodes: [{ id: 'name', label: 'Configured name exists', sub: 'eth0 vs ens18', kind: 'os' }, { id: 'up', label: 'Admin up + address', sub: 'networking.service', kind: 'service' }] },
      { label: 'Link', nodes: [{ id: 'carrier', label: 'Carrier', sub: 'cable / vNIC connected', kind: 'network' }] },
      { label: 'Switch', nodes: [{ id: 'member', label: 'swp6 member of br0', sub: 'bridge-ports', kind: 'network' }, { id: 'vlan', label: 'VLAN 20 access', sub: 'bridge-access 20', kind: 'network' }] },
      { label: 'Gateway', nodes: [{ id: 'gw', label: 'rtr01 eth1', sub: '10.0.20.1, ARP works', kind: 'service' }] },
    ],
    edges: [['name', 'up'], ['up', 'carrier'], ['carrier', 'member'], ['member', 'vlan'], ['vlan', 'gw']],
  },
  sequence: {
    title: 'Boot of srv01 after a NIC rename',
    lanes: [{ id: 'k', label: 'kernel', sub: 'driver' }, { id: 'u', label: 'udev', sub: 'naming' }, { id: 'n', label: 'networking', sub: 'ifup -a' }, { id: 'r', label: 'rtr01', sub: 'gateway' }],
    steps: [
      { from: 'k', to: 'u', label: 'new NIC (virtio) registered as eth0' },
      { from: 'u', to: 'k', label: 'rename eth0 → ens18 (slot policy)' },
      { from: 'n', to: 'k', label: 'ifup eth0: Cannot find device "eth0"', fail: true, note: 'networking.service fails; ens18 stays DOWN without an address.' },
      { from: 'r', to: 'k', label: 'ARP who-has 10.0.20.10?', fail: true, note: 'Nobody answers: rtr01 ip neigh FAILED, clients get "No route to host".' },
    ],
  },
  files: [
    { path: '/etc/network/interfaces', platform: 'Debian (the lab, sw01 bridge)', kind: 'config', contains: '`auto`/`iface` stanzas by interface name; bridge-ports, bridge-access/vids/pvid, bond-*, mtu.', accessed: 'Boot (networking.service), ifreload -a.', problems: 'Names an interface that no longer exists → "Cannot find device"; a bridge port missing from bridge-ports → port up but isolated.' },
    { path: '/etc/systemd/network/*.link', platform: 'Linux (systemd-udevd)', kind: 'config', contains: '`[Match] MACAddress=` and `[Link] Name=` (also MTUBytes, WakeOnLan).', accessed: 'When udev processes the device (boot, hotplug); copied into the initramfs.', problems: 'Stale MAC after a NIC replacement → the rule no longer matches and the NIC gets its default name.' },
    { path: '/usr/lib/systemd/network/99-default.link', platform: 'Linux', kind: 'config', contains: 'NamePolicy=keep kernel database onboard slot path; AlternativeNamesPolicy=…', accessed: 'Default naming policy for every NIC.', problems: 'Overridden by net.ifnames=0 on the kernel command line.' },
    { path: '/sys/class/net/<if>/', platform: 'Linux', kind: 'runtime', contains: 'operstate, carrier, address, mtu, speed, duplex, type, master (symlink), brif/ (bridge members).', accessed: 'Read by ip, monitoring agents, scripts.', problems: 'carrier/speed return "Invalid argument" when the interface is admin-down.' },
    { path: '/proc/net/bonding/bond0', platform: 'Linux', kind: 'runtime', contains: 'Bonding mode, currently active slave, MII status and link failure count per slave, LACP partner details.', accessed: 'Updated by the bonding driver.', problems: 'An 802.3ad slave with "Partner Mac Address: 00:00:00:00:00:00" = the switch is not doing LACP.' },
    { path: 'VM configuration (vmx, Proxmox qemu-server/<id>.conf, Hyper-V VM settings)', platform: 'Hypervisors', kind: 'config', contains: 'NIC model (e1000, vmxnet3, virtio), MAC, connected state, port group / bridge, VLAN tag.', accessed: 'At VM power-on and on hot changes.', problems: 'Changing the NIC model changes the guest\'s interface name; "disconnected" = NO-CARRIER in the guest.' },
  ],
  management: [
    {
      platform: 'Debian (srv01, sw01, rtr01: the lab)',
      tasks: [
        { task: 'Inventory', command: 'ip -br link\nip -br addr', explain: 'Name, state, MAC, flags; addresses.', sim: true },
        { task: 'Details of one interface', command: 'ip -d link show eth0', explain: 'altname, master, bridge_slave / vlan details.', sim: true },
        { task: 'Kernel state as files', command: 'cat /sys/class/net/eth0/operstate\ncat /sys/class/net/eth0/carrier', explain: 'up/1 = usable with link.', sim: true },
        { task: 'Driver and link', command: 'ethtool -i eth0\nethtool eth0', explain: 'Driver/NIC model; speed, duplex, Link detected.', sim: true },
        { task: 'Take an interface down / up (runtime)', command: 'ip link set dev eth0 down\nip link set dev eth0 up', explain: 'Admin state only; addresses configured by ifupdown stay but routes via the interface are removed while down.', risk: 'Over SSH through that interface: you lose the session. Use the console.', sim: true },
        { task: 'Did ifupdown succeed?', command: 'systemctl status networking\njournalctl -u networking -b', explain: '"Cannot find device" names the missing interface.', sim: true },
        { task: 'Apply /etc/network/interfaces changes', command: 'ifreload -a', explain: 'ifupdown2: brings the running state in line with the file (bridge ports, VLANs, addresses).', risk: 'A mistake in the file applies immediately to every interface.', sim: true },
        { task: 'Restart networking (ifupdown)', command: 'systemctl restart networking', explain: 'Re-runs ifdown/ifup for all auto stanzas.', risk: 'Interrupts all connectivity briefly; from a remote shell only with a rollback plan.', sim: true },
        { task: 'Bridge members, VLANs, MAC table', command: 'bridge link\nbridge vlan show\nbridge fdb show br0', explain: 'On sw01: is the port a member, in which VLAN, and has it learned the server\'s MAC?', sim: true },
        { task: 'Attach or detach a bridge port (runtime)', command: 'ip link set swp6 nomaster\nip link set swp6 master br0\nbridge vlan add dev swp6 vid 20 pvid untagged\nbridge vlan del dev swp6 vid 1', explain: 'nomaster: the port keeps carrier but is no longer switched. A new port joins VLAN 1 (the default PVID) until you set its VLAN.', risk: 'Runtime only: ifreload -a or a reboot restores what /etc/network/interfaces says.', sim: true },
        { task: 'A dummy interface', command: 'ip link add dummy0 type dummy\nip addr add 192.0.2.1/32 dev dummy0\nip link set dummy0 up', explain: 'A stable address independent of NICs.', sim: true },
      ],
    },
    {
      platform: 'Linux (real systems, not simulated)',
      tasks: [
        { task: 'Create a bridge and add a port', command: 'ip link add br0 type bridge\nip link set eth1 master br0\nip link set br0 up', explain: 'Runtime only; persist in /etc/network/interfaces, netplan or a .netdev file.' },
        { task: 'Bond status', command: 'cat /proc/net/bonding/bond0', explain: 'Mode, active slave, per-slave MII status, LACP partner.' },
        { task: 'veth pair / namespaces', command: 'ip link add veth0 type veth peer name veth1\nip netns add test; ip link set veth1 netns test', explain: 'How containers are wired; ip -n test link shows the other end.' },
        { task: 'Naming candidates', command: 'udevadm test-builtin net_id /sys/class/net/eth0', explain: 'ID_NET_NAME_ONBOARD/SLOT/PATH/MAC values udev would use.' },
        { task: 'Open vSwitch', command: 'ovs-vsctl show', explain: 'Bridges, ports and VLAN tags on OVS-based hosts.' },
      ],
    },
    {
      platform: 'Windows / Hyper-V',
      tasks: [
        { task: 'Adapters', command: 'Get-NetAdapter | Format-Table Name, InterfaceDescription, Status, LinkSpeed, MacAddress', explain: 'Status Up/Disconnected/Disabled = carrier and admin state.' },
        { task: 'Virtual switches and VM adapters', command: 'Get-VMSwitch\nGet-VMNetworkAdapter -VMName srv01\nGet-VMNetworkAdapterVlan -VMName srv01', explain: 'Switch type (External/Internal/Private), VM connection, access VLAN.' },
      ],
    },
    {
      platform: 'VMware ESXi',
      tasks: [
        { task: 'vSwitches, port groups, uplinks', command: 'esxcli network vswitch standard list\nesxcli network vswitch standard portgroup list\nesxcli network nic list', explain: 'Port group VLAN IDs and the physical uplinks with their link state.' },
      ],
    },
  ],
  actions: [
    { action: 'ip link set dev X up/down', when: 'Test or temporarily disable an interface.', effect: 'Immediate; runtime only.', risk: 'Cuts sessions through that interface.' },
    { action: 'Rename references after a NIC change', when: 'Interface name changed (migration, new NIC model).', effect: 'Configuration matches the device again.', risk: 'Forgetting a file (firewall iifname, DHCP interfaces) leaves a second, quieter failure.' },
    { action: 'Pin the name with a .link file', when: 'Names must survive hardware changes.', effect: 'Name follows the MAC.', risk: 'Must be updated when the NIC (MAC) is replaced; rebuild the initramfs.' },
    { action: 'ifreload -a / systemctl restart networking', when: 'Apply /etc/network/interfaces changes.', effect: 'Running state follows the file.', risk: 'Applies every mistake in the file at once; use the console.' },
    { action: 'Add/remove bridge ports', when: 'New server port, decommissioning.', effect: 'Port joins or leaves the switch.', risk: 'Removing the wrong port isolates a server while its link stays green.' },
  ],
  workflow: [
    { question: '1. Does the configured interface exist?', command: 'ip -br link\ngrep -n iface /etc/network/interfaces', healthy: 'Every configured name appears in ip -br link', broken: 'Configuration says eth0, the system has ens18 (or the reverse).', next: 'Rename in the configuration (and every other file that names it), or pin the name.', sim: true },
    { question: '2. Is it up and configured?', command: 'ip -br addr\nsystemctl status networking', healthy: 'UP with the expected address; networking active (exited)', broken: 'DOWN without address; networking failed: Cannot find device / ifup failed.', next: 'Fix the stanza, then systemctl restart networking (console).', sim: true },
    { question: '3. Is there carrier?', command: 'ip -br link\ncat /sys/class/net/eth0/carrier\nethtool eth0', healthy: 'LOWER_UP, carrier 1, Link detected: yes', broken: 'NO-CARRIER / 0: cable, switch port shut, VM NIC disconnected.', next: 'Physical layer or hypervisor NIC settings.', sim: true },
    { question: '4. Can it reach its neighbour at layer 2?', command: 'ping -c 2 10.0.20.1\nip neigh', healthy: 'Replies; gateway REACHABLE with a MAC', broken: 'FAILED with carrier on both ends → the switch/vSwitch is not connecting them.', next: 'Step 5 on the switch.', sim: true },
    { question: '5. Is the switch port a member, in the right VLAN?', command: 'bridge link\nbridge vlan show\nbridge fdb show br0', healthy: 'Port listed with master br0, correct PVID VLAN, server MAC learned on it', broken: 'Port missing from bridge link / vlan show, wrong VLAN, no MAC learned.', next: 'Fix bridge-ports / bridge-access and ifreload -a (on hypervisors: port group / VLAN tag).', sim: true },
    { question: '6. Does it survive a reboot?', command: 'grep -n -E "auto|iface|bridge-ports" /etc/network/interfaces\nsystemctl is-enabled networking', healthy: 'auto stanzas for every interface; configuration matches the running state', broken: 'Runtime fix only (ip link/bridge commands) → lost at reboot.', next: 'Persist the change in the configuration file.', sim: true },
  ],
  failures: [
    { symptom: 'Server unreachable after VM migration / NIC model change; console works', causes: ['Interface renamed (eth0 → ens18/ens192/enp1s0); configuration names the old interface'], diagnose: ['ip -br link', 'systemctl status networking', 'journalctl -u networking -b'], fix: 'Update the name in /etc/network/interfaces (and firewall/DHCP/monitoring), restart networking; consider a .link file.', verify: 'ip -br addr shows the address; clients connect' },
    { symptom: 'Link LED green, address correct, ARP fails both ways', causes: ['Switch port not a member of the bridge', 'Port in the wrong VLAN', 'VM on the wrong port group / VLAN tag'], diagnose: ['bridge link', 'bridge vlan show', 'bridge fdb show', 'hypervisor VM NIC settings'], fix: 'Add the port to bridge-ports / correct VLAN; ifreload -a.', verify: 'ip neigh REACHABLE; server MAC in bridge fdb on the right port' },
    { symptom: 'NO-CARRIER in the guest', causes: ['VM NIC disconnected (Connected/Start connected unchecked)', 'vSwitch without an uplink', 'Cable or switch port shut'], diagnose: ['ethtool eth0', 'VM settings', 'esxcli network nic list'], fix: 'Connect the virtual NIC / fix the uplink.', verify: 'LOWER_UP, Link detected: yes' },
    { symptom: 'Interface down after every reboot, fine after manual ifup', causes: ['No auto/allow-hotplug line for it', 'Stanza names the wrong interface'], diagnose: ['grep -n auto /etc/network/interfaces', 'journalctl -u networking -b'], fix: 'Add auto IFACE; correct the name.', verify: 'Reboot test' },
    { symptom: 'Broadcast storm, switches at 100% CPU after adding a second uplink to a bridge', causes: ['Loop with STP disabled (bridge-stp off)', 'Bond configured as balance-rr towards two independent switch ports'], diagnose: ['ip -d link show br0 (stp_state)', 'cat /proc/net/bonding/bond0', 'switch logs (MAC flapping)'], fix: 'Enable STP or remove the loop; use active-backup or LACP with a matching port-channel.', verify: 'Stable MAC table, normal traffic levels' },
    { symptom: 'Nested hypervisor / bridge inside a VM: inner VMs have no network', causes: ['vSwitch security policy rejects promiscuous mode, MAC changes or forged transmits'], diagnose: ['Port group security settings'], fix: 'Allow them on a dedicated port group only (or use MAC learning on vDS 6.7+).', verify: 'Inner VMs reach the gateway' },
  ],
  verification: [
    { check: 'Names match configuration', command: 'ip -br link; grep -n iface /etc/network/interfaces', expect: 'Every configured interface exists' },
    { check: 'Up with link and address', command: 'ip -br addr', expect: 'UP with the expected addresses' },
    { check: 'networking.service healthy', command: 'systemctl status networking', expect: 'active (exited)' },
    { check: 'Switch membership', command: 'bridge link; bridge vlan show (sw01)', expect: 'Server port a member, in its VLAN' },
    { check: 'Layer 2 to the gateway', command: 'ping -c 2 GATEWAY; ip neigh', expect: 'Replies; REACHABLE' },
    { check: 'Persistent', command: 'Reboot test', expect: 'Same state after reboot' },
  ],
  refIds: ['ip', 'bridge', 'ethtool', 'systemctl', 'journalctl', 'networkctl', 'netplan', 'nmcli', 'get-netadapter', 'file:etc-network-interfaces', 'file:netplan', 'file:networkmanager', 'proc:remote-network-change', 'proc:safe-config-change'],
};
