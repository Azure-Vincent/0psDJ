import type { ConceptId } from '../engine/scenarios/types';

/** Concept catalogue used for mastery tracking and remediation links. */
export const CONCEPTS: Record<ConceptId, { title: string; description: string; review: string; prerequisites: ConceptId[] }> = {
  'dns.resolution': { title: 'Name resolution path', description: 'How getaddrinfo uses /etc/hosts, resolv.conf, search domains and DNS servers.', review: 'lesson/transport/internals', prerequisites: [] },
  'dns.zone': { title: 'Authoritative DNS zones', description: 'Zone files, SOA serials, reloads, and what SERVFAIL/NXDOMAIN mean.', review: 'lesson/transport/internals', prerequisites: ['dns.resolution'] },
  'net.arp': { title: 'ARP and next hops', description: 'Resolving the next hop\'s MAC address; what ARP failure looks like to a client.', review: 'lesson/ipnet/internals', prerequisites: [] },
  'net.routing': { title: 'Routing in both directions', description: 'Longest-prefix match, default gateways, and why the return path matters.', review: 'lesson/ipnet/internals', prerequisites: ['net.arp'] },
  'net.icmp': { title: 'ICMP errors and their client symptoms', description: 'Host/port unreachable, admin-prohibited and time-exceeded, and how they map to errno messages.', review: 'lesson/ipnet/internals', prerequisites: ['net.routing'] },
  'tcp.handshake': { title: 'TCP handshake, RST and retransmission', description: 'SYN/SYN-ACK/ACK; refused vs timed out; who answers when nothing listens.', review: 'lesson/transport/internals', prerequisites: ['net.routing'] },
  'fw.stateful': { title: 'Stateful packet filtering', description: 'Chains, rule order, policies, established/related and drop vs reject.', review: 'lesson/nftables/internals', prerequisites: ['tcp.handshake'] },
  'fw.persistence': { title: 'Runtime vs persistent configuration', description: 'Why "works now" is not "works after reboot" for routes, firewall rules and services.', review: 'lesson/nftables/internals', prerequisites: [] },
  'svc.systemd': { title: 'systemd service lifecycle', description: 'enabled vs active, ExecStartPre tests, reload vs restart, reading unit status.', review: 'lesson/ssh/deploy', prerequisites: [] },
  'svc.listening': { title: 'Listening sockets', description: 'Bind addresses and ports, and how to verify them with ss.', review: 'lesson/transport/internals', prerequisites: ['tcp.handshake'] },
  'ssh.kex': { title: 'SSH algorithm negotiation and key exchange', description: 'KEXINIT, first-match negotiation, ephemeral keys, exchange hash.', review: 'lesson/ssh/visualize', prerequisites: ['tcp.handshake'] },
  'ssh.hostkeys': { title: 'Host keys and known_hosts', description: 'How the client authenticates the server and what a mismatch means.', review: 'lesson/ssh/internals', prerequisites: ['ssh.kex'] },
  'ssh.userauth': { title: 'SSH user authentication', description: 'Method negotiation, publickey query and signature, password via PAM.', review: 'lesson/ssh/visualize', prerequisites: ['ssh.kex'] },
  'ssh.authorized-keys': { title: 'authorized_keys', description: 'Where sshd looks for keys and how keys are matched.', review: 'lesson/ssh/config', prerequisites: ['ssh.userauth'] },
  'linux.permissions': { title: 'Unix permissions and ownership', description: 'Mode bits, owners, and the StrictModes / private-key permission checks.', review: 'lesson/ssh/config', prerequisites: [] },
  'ssh.config': { title: 'sshd configuration semantics', description: 'First-match, Include, Match blocks, sshd -t / -T, reload.', review: 'lesson/ssh/config', prerequisites: ['svc.systemd'] },
  'ssh.authz': { title: 'SSH authorization lists', description: 'AllowUsers/AllowGroups/DenyUsers and where rejections are logged.', review: 'lesson/ssh/config', prerequisites: ['ssh.userauth'] },
  'net.cidr': { title: 'CIDR prefixes and address ranges', description: 'Which addresses a prefix like 10.0.10.0/23 actually covers.', review: 'lesson/ipnet/internals', prerequisites: [] },
  'fw.path': { title: 'Where filtering happens', description: 'Host firewalls (input/output) vs firewalls in the path (forward), and how to tell which one dropped a packet.', review: 'lesson/nftables/internals', prerequisites: ['fw.stateful', 'net.routing'] },
  'net.dhcp': { title: 'DHCP address assignment', description: 'DORA, broadcast scope, pools and reservations, lease files and the options clients receive.', review: 'lesson/dhcp/internals', prerequisites: ['net.arp'] },
  'net.nat': { title: 'NAT and port forwarding', description: 'Masquerade/SNAT and DNAT, the NAT table, and where translation happens relative to filtering.', review: 'lesson/nat/internals', prerequisites: ['net.routing', 'fw.stateful'] },
  'logs.journal': { title: 'Reading the journal', description: 'journalctl filters and finding the line that explains a failure.', review: 'lesson/ssh/troubleshoot', prerequisites: [] },
};
