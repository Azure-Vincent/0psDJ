// The study roadmap: the order in which to take the lessons and labs, in
// phases. Each phase says why it comes where it does; every lab comes after
// the lessons it relies on (checked by tests/roadmap.test.ts), so following the
// roadmap never sends a learner into something they have not been taught.

export type RoadmapStep =
  | { kind: 'lesson'; id: string; why: string }
  | { kind: 'lab'; id: string; why: string }
  /** Open-ended practice with no completion record (case studies, the builder): never blocks "next". */
  | { kind: 'practice'; title: string; link: string; why: string };

export interface RoadmapPhase {
  id: string;
  title: string;
  /** What the learner can do at the end of the phase. */
  goal: string;
  /** Why the phase comes at this point of the path. */
  why: string;
  steps: RoadmapStep[];
}

export const ROADMAP: RoadmapPhase[] = [
  {
    id: 'foundations',
    title: 'Network foundations',
    goal: 'Explain how a packet gets from one machine to another: addresses, routes, ports, names and automatic configuration.',
    why: 'Every service in this course is reached over the network. When something breaks, the first question is always "can the packets get there?", so this comes first.',
    steps: [
      { kind: 'lesson', id: 'ipnet', why: 'Addresses, subnets, ARP and routing: the language everything else is written in.' },
      { kind: 'lesson', id: 'transport', why: 'Ports, TCP and UDP, and DNS: how a program finds and talks to a service.' },
      { kind: 'lesson', id: 'dhcp', why: 'How clients get their address, gateway and DNS server without manual setup.' },
      { kind: 'lesson', id: 'nat', why: 'How private networks reach the Internet and how services are published.' },
      { kind: 'lesson', id: 'vlan', why: 'How one switch carries several separate networks.' },
    ],
  },
  {
    id: 'linux-server',
    title: 'Run and protect a Linux server',
    goal: 'Log in securely, manage services and logs, and filter traffic on a Linux server; build one from scratch.',
    why: 'With the network understood, the next layer is the server itself: how you reach it, how its services run, and what the firewall lets in.',
    steps: [
      { kind: 'lesson', id: 'ssh', why: 'The way administrators reach Linux servers, and the most common ticket.' },
      { kind: 'lesson', id: 'systemd', why: 'Starting, enabling and reading the logs of the services you will deploy.' },
      { kind: 'lesson', id: 'nftables', why: 'The host and router firewall: allowed, dropped, and why.' },
      { kind: 'lab', id: 'lab1', why: 'Your first build: a Debian server from switch port to hardened web server, step by step.' },
      { kind: 'lab', id: 'ilab1', why: 'Combine addressing, DHCP, DNS, routing and firewall rules for a new office network, then fix an incident.' },
    ],
  },
  {
    id: 'network-depth',
    title: 'Deeper networking',
    goal: 'Work with IPv6, virtual interfaces, MTU problems and TLS certificates, and recover a misconfigured network safely.',
    why: 'These subjects build on the foundations and explain the harder failures: the ones where ping works but the service still does not.',
    steps: [
      { kind: 'lesson', id: 'ipv6', why: 'The second address family every modern network runs.' },
      { kind: 'lesson', id: 'netif', why: 'Bridges, bonds and virtual switches between the cable and the IP address.' },
      { kind: 'lesson', id: 'mtu', why: 'Why large transfers hang when small ones work.' },
      { kind: 'lesson', id: 'tls', why: 'Certificates and chains: needed for HTTPS, LDAPS and most secure services later on.' },
      { kind: 'lesson', id: 'netops', why: 'Changing network configuration without locking yourself out, and recovering when it goes wrong.' },
    ],
  },
  {
    id: 'core-services',
    title: 'Core Linux services',
    goal: 'Deploy a web server and reverse proxy, keep time, centralise logs and share files, and integrate a new server with all of them.',
    why: 'These are the services every organisation runs. Each depends on the network and the server skills from the earlier phases.',
    steps: [
      { kind: 'lesson', id: 'webproxy', why: 'nginx as a web server and reverse proxy.' },
      { kind: 'lab', id: 'ilab2', why: 'Deploy and secure a web server end to end: DNS, permissions, firewall and SSH keys.' },
      { kind: 'lesson', id: 'ntp', why: 'Correct time: required by logs, certificates and Kerberos.' },
      { kind: 'lesson', id: 'logging', why: 'Collecting every server\'s logs in one place.' },
      { kind: 'lesson', id: 'nfs', why: 'File sharing between Linux machines.' },
      { kind: 'lesson', id: 'smb', why: 'File sharing for Windows clients.' },
      { kind: 'lab', id: 'lab5', why: 'Integrate a new server with DNS, NTP, logging, NFS, SMB and the reverse proxy.' },
    ],
  },
  {
    id: 'windows-identity',
    title: 'Windows and identity',
    goal: 'Administer Windows Server, build an Active Directory domain, and explain how Kerberos and Group Policy work.',
    why: 'Most organisations manage users and computers with Active Directory. It depends on DNS and time, which you now know.',
    steps: [
      { kind: 'lesson', id: 'windows-rdp', why: 'Windows Server administration and remote access.' },
      { kind: 'lesson', id: 'windows-firewall', why: 'The Windows host firewall, and its profiles and logs.' },
      { kind: 'lesson', id: 'ad-kerberos', why: 'Domains, domain controllers and how logons work.' },
      { kind: 'lesson', id: 'kerberos', why: 'Kerberos tickets and the DNS records clients use to find the KDC.' },
      { kind: 'lesson', id: 'gpo', why: 'Applying settings to many computers at once.' },
      { kind: 'lab', id: 'lab2', why: 'Build a domain: promote a DC, create accounts, join a server, grant RDP.' },
      { kind: 'lab', id: 'ilab3', why: 'A complete AD environment with an OU and a GPO, then a Kerberos incident.' },
    ],
  },
  {
    id: 'perimeter',
    title: 'Perimeter and segmentation',
    goal: 'Separate Internet, DMZ and internal networks with a dedicated firewall, and publish a service safely.',
    why: 'Host firewalls protect one machine; a perimeter firewall protects whole networks. It reuses NAT, VLAN and firewall-rule thinking from earlier phases.',
    steps: [
      { kind: 'lesson', id: 'pfsense', why: 'pfSense rules, NAT and its logs.' },
      { kind: 'lab', id: 'lab3', why: 'Build a DMZ, aliases, a policy and a port forward from the webConfigurator.' },
      { kind: 'lab', id: 'ilab6', why: 'Segment the network as a flow matrix, then find why DNS broke after a rule change.' },
    ],
  },
  {
    id: 'applications',
    title: 'Applications and data',
    goal: 'Run databases, containers and mail, and connect applications across Linux and Windows.',
    why: 'Applications sit on top of everything else: they need the network, the firewall, names, storage and often the proxy.',
    steps: [
      { kind: 'lesson', id: 'database', why: 'PostgreSQL: roles, privileges, remote access and backups.' },
      { kind: 'lab', id: 'lab7', why: 'Set up a database server for one application, least privilege included.' },
      { kind: 'lesson', id: 'docker', why: 'Containers, images, networks and volumes.' },
      { kind: 'lab', id: 'lab4', why: 'Deploy a containerized application and harden its host.' },
      { kind: 'lab', id: 'ilab5', why: 'A containerized business app behind the reverse proxy, with its data kept.' },
      { kind: 'lab', id: 'ilab4', why: 'Four tickets across Linux, Windows, PostgreSQL and Samba.' },
      { kind: 'lesson', id: 'email', why: 'Mail delivery and mailboxes: Postfix and Dovecot.' },
    ],
  },
  {
    id: 'operations',
    title: 'Operate and secure',
    goal: 'Back up and restore, monitor and alert, centralise network logins, and keep an environment secure over time.',
    why: 'Building something is half the job; keeping it running and recoverable is the other half.',
    steps: [
      { kind: 'lesson', id: 'backup', why: 'Backups you can actually restore.' },
      { kind: 'lab', id: 'lab8', why: 'Put a server under encrypted, scheduled backup and test a restore.' },
      { kind: 'lesson', id: 'monitoring', why: 'Prometheus, alerts and SNMP.' },
      { kind: 'lab', id: 'lab9', why: 'Bring a server under monitoring and test an alert end to end.' },
      { kind: 'lesson', id: 'identity', why: 'LDAP/LDAPS and RADIUS for network device logins.' },
      { kind: 'lab', id: 'lab10', why: 'Router logins through RADIUS and Active Directory.' },
      { kind: 'lab', id: 'ilab9', why: 'Accounts, SSH, logging and backups, then a hardening change that broke monitoring.' },
    ],
  },
  {
    id: 'incidents',
    title: 'Recover from incidents',
    goal: 'Restore several broken services in the right order, from evidence, without making things worse.',
    why: 'Real outages involve several systems at once. This phase uses everything before it and trains the order of investigation.',
    steps: [
      { kind: 'lesson', id: 'recovery', why: 'Safe recovery: what to restart, what not to, and in which order.' },
      { kind: 'lab', id: 'lab6', why: 'A power cut took everything down: recover in dependency order.' },
      { kind: 'lab', id: 'ilab7', why: 'A DNS failure that looks like many different problems.' },
      { kind: 'lab', id: 'ilab8', why: 'Three services down at once, then a firewall review goes wrong.' },
    ],
  },
  {
    id: 'capstone',
    title: 'Capstone',
    goal: 'Deploy a complete service independently, and investigate unfamiliar failures with no guidance.',
    why: 'The end of the path: the same skills without step-by-step help.',
    steps: [
      { kind: 'lab', id: 'ilab10', why: 'Deploy a complete service with monitoring and admin access, then fix two faults at once. Try it in independent mode.' },
      { kind: 'practice', title: 'Case studies', link: 'cases', why: 'Unguided investigations of real-world failures, from the symptoms to the root cause.' },
      { kind: 'practice', title: 'Infrastructure Builder', link: 'builder', why: 'Design your own networks and trace packets through them.' },
    ],
  },
];

/** Every step in order, with its phase. */
export const ROADMAP_STEPS: { phase: RoadmapPhase; step: RoadmapStep; index: number }[] =
  ROADMAP.flatMap((phase) => phase.steps.map((step) => ({ phase, step }))).map((x, index) => ({ ...x, index }));

export function stepKey(s: RoadmapStep): string {
  return s.kind === 'practice' ? `practice:${s.link}` : `${s.kind}:${s.id}`;
}
