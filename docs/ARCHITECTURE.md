# Infrastructure Lab: design

This document covers the six design deliverables requested before implementation:
architecture and stack, curriculum dependency map, interface layout, data model,
troubleshooting-engine design, and the phased plan. Status markers show what
exists today (✅ implemented, 🟡 partial, ⏳ planned).

---

## 1. Architecture and technology stack

| Concern | Choice | Why |
|---|---|---|
| Desktop shell | **Electron** (`electron/main.cjs`) | One codebase for Windows, Linux and macOS; ships its own Chromium, so rendering of SVG diagrams and terminals is identical everywhere; fully offline (`loadFile` of the built bundle). Tauri was considered (smaller binaries) but needs a Rust toolchain per platform and WebView differences (WebKitGTK/WebView2/WKWebView) would make diagram and terminal behaviour platform-dependent. |
| UI | **React 18 + TypeScript**, plain CSS with design tokens | Mature, well-known, no UI-kit lock-in. Light/dark themes via CSS custom properties and `prefers-color-scheme`. |
| Build | **Vite** (`base: './'`) | Fast dev server; production bundle loads from `file://` inside Electron. |
| Simulation engine | **Pure TypeScript, no DOM** (`src/engine`) | Deterministic and unit-testable in Node. The same engine drives the terminal, the sequence diagram, the dependency map, the packet lab and the verification of troubleshooting fixes. |
| Tests | **Vitest** (`tests/`) | Engine, scenarios (fault → symptom → fix → verify), grading, PCAP checksums, display filters. |
| Persistence | `localStorage` (Electron stores it in the app's user-data folder) + JSON export/import | No server, no account, no paid API. |

```
┌──────────────────────────── Electron (main process: window, external links) ──────────────────────────┐
│ Renderer (React)                                                                                     │
│  pages/  Dashboard · Curriculum · Lesson (7 sections) · Troubleshooting · Commands · Packet Lab ·     │
│          Glossary · History · Settings · Search                                                       │
│  components/  Terminal · LabTerminals · SequenceDiagram · PacketLayers · DependencyMap ·              │
│               ConfigExplorer · Assessment · Topology · Editor · Markdown                              │
│  learning/  grading (assessments, command exercises) · progress (mastery, history, persistence)      │
│  content/   lessons · assessments · command reference · glossary · curriculum · concepts (data only)  │
│  engine/    deterministic infrastructure simulator (below)                                            │
└──────────────────────────────────────────────────────────────────────────────────────────────────────┘

engine/
  net/ip.ts, ip6.ts    IPv4 / IPv6 address and prefix math (RFC 5952 text form, EUI-64, solicited-node)
  config/              parsers that real admins edit: sshd_config, nftables, BIND zones, ifupdown(2), dhcpd.conf, resolv.conf, hosts
  sim/network.ts       hop-by-hop forwarding (IPv4 + IPv6): routing (LPM), ARP / Neighbor Discovery, TTL, conntrack, nft hooks, NAT, ICMP/ICMPv6 errors, captures
  sim/l2.ts            switch: VLAN-aware bridge state, cabling, broadcast domains derived from port membership and tagging
  sim/slaac.ts, dhcp.ts router discovery / SLAAC (radvd) and DHCP (dhcpd, dhclient)
  sim/tcp.ts           3-way handshake, RST, SYN retransmission/backoff, data segments, FIN teardown
  sim/dns.ts           glibc-like stub resolver (hosts → resolv.conf servers, search list) + authoritative answers
  sim/services.ts      systemd-like lifecycle: start/stop/reload/enable, ExecStartPre tests, bind(), boot
  sim/ssh.ts           OpenSSH 9.2 client+server behaviour, journal lines, protocol trace
  sim/trace.ts         event recorder shared by the diagram, dependency map and packet lab
  shell/               simulated bash: tokenizer (quotes, pipes, redirection, && ||), 50+ commands
  scenarios/           cause catalogue, scenario definitions, verification, diagnosis grading
  lab/                 baseline lab, dependency map faults, packet-capture presets
  pcap.ts, filter.ts   libpcap writer with valid checksums; Wireshark display-filter subset
```

**Determinism.** No `Math.random`, no wall-clock use inside the engine: ports, ISNs,
IDs and key material come from seeded functions of world state. Interactive
prompts (host-key confirmation, passwords, sudo) are implemented by *replaying*
a command line with the collected answers on a fresh copy of the world; this is
only correct because the engine is deterministic, and it is tested.

**Honesty about simulation.** The app never claims to run Debian, Windows,
pfSense or Docker (win01 is a simulated Windows Server and fw01 a simulated pfSense, labelled as such). Deployment guides target real VMs and are labelled as such;
the sandbox and scenarios are labelled as simulations, and simplifications are
stated where they matter (see §5.6).

---

## 2. Curriculum dependency map

Modules (✅ / 🟡 / ⏳ per topic are listed in-app under *Curriculum*):

```
            ┌──────────────► B Remote access (SSH ✅, RDP ⏳, WinRM ⏳, VPN ⏳ …) ─┐
A Networking┤──────────────► D Firewalls (nftables 🟡, pfSense 🟡 …) ──────────────┼─► F Enterprise infrastructure
fundamentals├──────────────► E Virtualization & containers (⏳) ─────────────────────┤      (DNS 🟡, Linux admin 🟡, others ⏳)
            └─► C Identity & authentication (PAM 🟡, AD/Kerberos/LDAP ⏳) ◄── B ──────┘
```

Concept-level prerequisites (used for remediation advice on the dashboard;
defined in `src/content/concepts.ts`):

```
net.arp → net.routing → net.icmp
                     └→ tcp.handshake → fw.stateful
                                     └→ svc.listening
                                     └→ ssh.kex → ssh.hostkeys
                                               └→ ssh.userauth → ssh.authorized-keys
                                                              └→ ssh.authz
dns.resolution → dns.zone        svc.systemd → ssh.config        linux.permissions   fw.persistence   logs.journal
```

When a concept is "struggling" (≥ 2 errors, smoothed accuracy < 50 %), the
dashboard recommends it *and* any prerequisite that is not yet proficient.

---

## 3. Interface layout

```
┌──────────────┬─────────────────────────────────────────────────────────────────┐
│ Brand        │ Page                                                            │
│ [ search ]   │                                                                 │
│ Dashboard    │ Lesson: tabs Overview · How it works (+architecture) ·          │
│ Curriculum   │   Visualize (sequence diagram, dependencies) · Deploy           │
│ LEARN        │   (platform guides + sandbox terminals) · Config (explorer,     │
│  (by module) │   file catalogue, directives) · Operate (management, reload/    │
│ PRACTICE     │   restart, verify) · Troubleshoot (workflow, error→layer,       │
│  Troublesh.  │   failures, case studies, tickets) · Assessment (self-check)    │
│  Case stud.  │ Case study: 12 elements, environment diagram, linked ticket     │
│  Packet Lab  │ Troubleshooting workspace (3 columns):                          │
│ REFERENCE    │  ticket/briefing/topology/hints │ terminals: ws01 · srv01 ·     │
│  Ref. library│  field manual (workflows, refs) │ ns1 · rtr01 consoles          │
│  Cert. map   │                                 │                               │
│  Glossary    │                                 │                               │
│  History     │                                 │ │ notes · evidence log ·      │
│  Settings    │                                 │ │ diagnosis · verify · RCA    │
│ offline note │                                                                 │
└──────────────┴─────────────────────────────────────────────────────────────────┘
```

**What goes in each lesson tab.** Each tab answers one question, and a piece of information lives in exactly one tab (`tests/learning.test.ts` rejects a `###` heading repeated across tabs):

| Tab | Answers | Sources |
|---|---|---|
| Overview | What is it, why does it matter, where will I meet it? | primer (one-liner, analogy, key ideas, misconceptions), `what`, a map of the other tabs |
| How it works | What happens step by step; which components, ports and processes? | primer walkthrough, `internals`, internals widgets, guide architecture/ports/processes, references |
| Visualize | What does it look like on the wire; what does it depend on? | simulator runs, guide dependency diagram and message sequence |
| Deploy | How do I install and set it up per platform? | `deployment` + sandbox |
| Config | Which files and settings control it; what do bad values break? | `configIntro`, config tool, one file catalogue (guide files + configFiles), directives |
| Operate & recover | How do I check, change, reload or restart it safely and confirm it is healthy? | guide purpose, `operateIntro`, management tasks, reload/restart/reboot, verification |
| Troubleshooting | Where do I start, what does this error mean, how do I tell causes apart? | `troubleshootingIntro`, guide workflow, error map, guide failures, case studies, tickets |
| Assessment | Do I understand it? | primer self-check, graded assessment |

Principles: no decorative controls; every button does something; planned
features are labelled "planned" and have no buttons; the answer to a ticket is
never visible until it is solved or explicitly revealed (the topology shows
addresses and roles only, never runtime state).

---

## 4. Data model

All content is plain data (`src/content/types.ts`) so new services are added by
writing data and, where needed, engine modules: not by changing the UI.

```ts
Lesson { id, moduleId, title, level, concepts[], what, internals,            // markdown-lite text
         deployment: DeploymentGuide[] { platform, prerequisites[], steps[] { command, what, why, expected, simulated } },
         configFiles[], directives[] { name, compiledDefault, distroDefault, recommended, explanation, security },
         troubleshootingIntro, errorMap[], scenarioIds[], assessmentId, references[] }

         mode?: 'simulated' | 'reference', guide?: ServiceGuide, caseStudyIds?[], objectives?[] }

ServiceGuide { purpose, architecture[] {q, a}, ports[], processes[],
               dependencies: LayeredDiagram, sequence?: StaticSequence,
               files[] { path, platform, kind (config|log|unit|registry|eventlog…), contains, accessed, problems, perms },
               management[] { platform, tasks[] { task, command, explain, risk?, sim? } },
               actions[] (reload vs restart vs interface restart vs reboot), workflow[] { question, command, healthy, broken, next, sim? },
               failures[] { symptom, causes[], diagnose[], fix, verify }, verification[], refIds[] }
CaseStudy { id, letter, scenarioId?, outputSource, symptoms, environment, expected, dependencies[],
            investigation[] { host, command, output, interpretation }, rootCause, repair[], restart, verify[], prevention[], lessonIds[], refIds[] }
FileRef { id 'file:…', path, platform, kind, services[], purpose, contents, accessed, permissions, problems, example?, relatedCommands[] }
Procedure { id 'proc:…', title, platform, services[], symptoms[], purpose, steps[] { title, command?, why }, risks, verify }
CertExam { code, version, officialUrl, domains[] { weight, objectives[] { id 'N10-009:5.3', coverage, links[], note } } }

Question = single | multi | order | text | nft-rule | sshd-config            // practical kinds graded by the engine
CommandRef { name, platform, purpose, syntax, args[], example, interpretation, limitations, simulator?,
             errors[], permissions, risks, compat, services[], protocols[], symptoms[] }   // reference-library facets
CommandExercise = choose-command (acceptCommands, mustMatch) | spot-abnormal (output[], abnormal[])
CurriculumModule { id, title, dependsOn[], topics[] { title, level, status, link? } }

Scenario { id, title, difficulty, ticket, briefing[], goals[] { localUser, user, target, method },
           setup(world)  // injects faults by running shell commands
           rootCauses[], acceptable{cause: note}, candidates[], feedback{cause: text},
           hints[3], solution[] { host, user, commands[] }, explanation { rootCause, manifestation, evidence, prevention },
           constraints[] (security/persistence checks), concepts[] }
Cause   { id, title, category, signature (evidence it produces), check (how to test), concept }

World   { hosts{}, segments{}, links[] (cables), clock, counter, sessions[] }
Host    { fs{path: {type, mode, owner, group, content}},  users{},            // persistent
          ifaces[] {address, addrs6[], vlan?, segment (derived)}, routes[], routes6[],
          neighbors[], nft, conntrack[], nat[], services{}, ipForward, ip6Forward, bridge?,   // runtime
          journal[], capture[] }

Progress { lessons{visited[]}, concepts{id: {correct, incorrect, misconceptions[]}},
           questions{}, exercises{}, predictions{},
           attempts[] { scenarioId, status, hintsUsed, diagnoses[], verifications[], commands[], notes } ,
           settings { theme } }
```

---

## 5. Stateful troubleshooting engine

### 5.1 One model, many views
A `World` holds hosts with a virtual filesystem (persistent configuration) and
runtime state (addresses, routes, loaded firewall, running services). Every
observation is computed from this state at the moment it is requested:

| The learner runs… | …which is computed from |
|---|---|
| `ssh`, `nc`, `curl`, `ping`, `traceroute`, `tracepath`, `dig` | packets routed hop by hop through `transmit()` (routes, ARP, nft input/forward/output, conntrack, TTL, interface MTU and DF with ICMP "fragmentation needed"), listeners from running services, the *loaded* sshd/BIND/nginx configuration (including the certificates nginx held in memory at its last successful reload) |
| `curl https://`, `openssl s_client/verify/x509` | the TLS handshake over TCP (`src/engine/shell/cmdHttp.ts`), chain building against the client's trust store file (`src/engine/sim/pki.ts`), HTTP responses from nginx's server blocks and web root (`src/engine/sim/http.ts`) |
| `systemctl status`, `journalctl` | service runtime state and the journal entries that operations actually wrote |
| `ss`, `ip`, `nft list`, `conntrack -L`, `tcpdump` | runtime tables and per-interface capture buffers filled by the packets above |
| `cat`, `ls -l`, `stat`, `sshd -T` | the filesystem and the real parsers |
| PowerShell on win01 (`Get-Service`, `Get-NetFirewallRule`, `Test-NetConnection`, `ipconfig`, `netsh`, `sc.exe`, `reg`), `xfreerdp` from Linux | the Windows model in `host.win` (`src/engine/win/model.ts`): services and their start types, the registry values the lab uses, firewall profiles and rules compiled into the same packet filter, adapter settings, event logs; the RDP stages in `src/engine/win/rdp.ts` |

So changing a firewall rule, a route, a file mode or a service state changes the
connection result, the counters, the captures and the logs together, because
they are all consequences of the same computation.

### 5.2 Persistent vs runtime state
`bootHost()` discards runtime state and rebuilds it from files:
`/etc/network/interfaces` → addresses/routes, `/etc/sysctl.d` → forwarding,
`/etc/nftables.conf` (if nftables is enabled) → ruleset, enabled units → started
(running their config tests). This makes "fixed now, broken after reboot"
faults real.

### 5.2b Windows hosts and PowerShell
A Windows host (`kind: 'windows'`) shares the network stack with the Linux
hosts; what differs lives in `host.win`. Persistent configuration (what Windows
keeps in the registry: service start types, firewall profiles and rules, adapter
IP settings, `fDenyTSConnections`, the RDP `PortNumber`) is applied by
`bootWindows()`: addresses and routes are set, Automatic services start in
dependency order, TermService starts when Remote Desktop is enabled, and
Windows Defender Firewall is compiled into an nft-style ruleset (block rules
before allow rules, rules filtered by the active network profile, rule display
names as comments) that `transmit()` evaluates like any other host's. Kernel
listeners (IIS/http.sys, WinRM, SMB) belong to System, PID 4.

The console runs a PowerShell 5.1 interpreter (`src/engine/win/ps`): a
mode-sensitive parser (command vs. expression mode), plain-data objects with
.NET type names (so a world snapshot stays `structuredClone`-able), parameter
binding with prefixes, aliases, positional parameters and common parameters,
Out-Default formatting with registered views (table/list/grouped), and error
records in the 5.1 format. Cmdlets are grouped by module (`cmdlets/*.ts`);
native programs (`ipconfig`, `ping`, `netsh`, `sc.exe`, `net`, `reg`, ...)
receive string arguments and return text, as on Windows. `Shell.execute()`
switches to PowerShell when the frame's host is Windows and keeps the session
(variables, location, history) in the frame.

Active Directory (`src/engine/win/ad.ts`) lives in the DC's `host.win.ad`;
members hold only their membership and machine password. Every domain
operation goes over the simulated network from the member: an SRV query for
`_ldap._tcp.dc._msdcs.<domain>` to the member's own DNS servers, then an LDAP
connection to the DC, then the comparison of the machine password (the secure
channel). Domain logons over RDP are NTLM pass-through along that path, so a
wrong DNS server, a DC firewall, a reverted snapshot or a locked account each
fail at their own stage with their own events. The DC's DNS Server answers
from its zones and recurses through its forwarders.

### 5.3 Fault injection
Scenarios inject faults with the same shell commands an administrator would
type (`systemctl restart ssh`, `chmod 777 …`, `rndc reload`, `reboot`), so the
journal contains a coherent history (e.g. the failed restart with the
`sshd -t` error and line number). Faults can be layered (the "Monday" ticket has
two, and fixing one changes the symptom from *timeout* to *refused*).

### 5.4 Verification
`verifyScenario()` checks the goal (a real `ssh` run in `BatchMode`) **now**,
then on a copy where **every host is rebooted**, then evaluates **constraints**
(e.g. firewall still default-deny, `PasswordAuthentication no` still enforced,
modern KEX still offered, other users still able to log in). A fix that opens
the firewall completely or only exists at runtime does not pass.

### 5.4b Guided labs
A guided lab (`GuidedLab` in `src/engine/labs/types.ts`) builds its own world
(Lab 1: the corp.lab network plus a fresh srv02) and is a list of steps. Each
step has an objective, background, tasks, hints, **checks** (functions of the
world that run commands on a copy, never on the learner's machines) and a
**reference solution** (shell commands). `checkStep()` evaluates one step; the
final step sets `afterReboot`, so its check reboots every host on a copy and
re-runs all earlier checks. Progress stores completed step ids; the world itself
is kept for the browser session and rebuilt on demand by replaying the reference
solutions of completed steps. `tests/labs.test.ts` proves that every step fails
before its solution and passes after it.

### 5.4c Infrastructure Builder
A builder design (`Design` in `src/engine/builder/design.ts`) is plain JSON:
nodes (kind, name, position, interfaces with IPv4/prefix, switch ports with
access VLAN or trunk VLANs, gateway, static routes, services, input firewall,
and on routers a forward policy with exceptions and source NAT) and cables
between interfaces. `validateDesign()` returns errors (which block building)
and warnings. `buildDesignWorld()` creates one Debian host per node with
`createHost()` and writes the configuration as files: `/etc/network/interfaces`
(static addresses, `gateway`, `up ip route add`, `eth0.20` sub-interfaces),
ifupdown2 bridge configuration on switches, `/etc/nftables.conf`, the router's
`ip_forward` sysctl, `/etc/hosts` with every machine, sshd and nginx. Cables to a
switch become `World.links`; a cable between two machines becomes a private
point-to-point segment. Then every host boots (switches first), so the running
state comes from the files exactly as in the lab. `traceCommand()` runs one
command with the recorder on a copy of the world and extracts the firewall,
NAT and drop decisions from the hop notes. Cables between switches are not
modelled yet: `segmentForVlan()` gives each switch its own broadcast domain per VLAN.

### 5.5 Diagnosis, hints, misconceptions
The learner records hypotheses from a catalogue of plausible causes. Wrong
choices are answered with *what that cause would look like and how to test it*
(or scenario-specific feedback), never with the answer. Hints are progressive
(method → where to look → nearly the fix). The root cause, manifestation,
identifying evidence, prevention and a reference repair are shown only after
resolution or an explicit, recorded reveal. Wrong causes are recorded as
misconceptions against their concept for mastery tracking.

### 5.6 Fidelity and simplifications
Modelled faithfully: longest-prefix routing, ARP (incl. failure timing), TTL,
ICMP errors and their errno mapping (RST/port-unreachable → refused,
host-unreachable/admin-prohibited → no route, silence → timeout after
6 SYN retransmissions ≈ 127 s), stateful nftables evaluation with counters and
logging, sshd_config first-match/Include/Match semantics and `sshd -t` errors,
OpenSSH 9.2 negotiation and authentication flow and its log lines, StrictModes
path checks, glibc resolver order and search list, BIND zone parsing and SERVFAIL
on load errors, systemd enable/active semantics.

Simplified (Windows): one domain controller and one domain (no replication, trusts, sites or FSMO transfers); domain logons are NTLM pass-through (Kerberos for Windows logons, Group Policy objects and LDAP queries beyond the DC locator ping are not modelled); RDP is modelled as its stages (TCP, TLS, NLA with the local password, the logon right) without graphics; PowerShell implements the cmdlets and parameters the lessons and tickets use, without functions, modules, remoting or try/catch; registry and event logs cover the keys and events the lab uses.

Simplified: Kerberos cryptography is synthetic (no cross-realm trust, renewal, delegation or PAC); NTP packets are not modelled (systemd-timesyncd sets the clock when it starts); one IPv4 address per interface; no spanning tree, DHCPv6 relays or prefix delegation, DAD, MLD or privacy addresses; one TCP segment per SSH message, no congestion control or
window dynamics; cryptographic values are synthetic (fingerprints are genuine
SHA-256 of synthetic key blobs); `tcpdump` shows a buffer of recent traffic
instead of live capture (terminals are not concurrent); a subset of each tool's
options is implemented and unsupported options say so.

---

## 6. Phased implementation plan

| Phase | Scope | Status |
|---|---|---|
| 0 | Foundation: Electron/React/Vite app shell, navigation, themes, search, local progress, glossary, curriculum map | ✅ |
| 1 | Engine core: IPv4 forwarding, ARP, ICMP, conntrack, nftables, DNS, systemd services, journal, simulated shell | ✅ |
| 2 | **Vertical slice: SSH**: 7-section lesson, protocol visualisation, deployment guides (Debian/RHEL/Windows) + sandbox, config explorer, 14 stateful troubleshooting tickets with verification, assessment with engine-graded practical questions, command reference & practice, packet lab with PCAP export, dependency map | ✅ |
| 3a | Lesson registry (data-driven lesson pages with per-lesson widgets); **Module D nftables lesson** with hook diagram, CIDR calculator, rule-by-rule packet tester, traced-run visualizer, 5 firewall tickets with HTTP/DNS goals and unsafe-fix constraints; atomic `reload` vs flushing `restart` for nftables.service | ✅ |
| 3b | **Module A**: "IP networking" and "TCP, UDP and DNS" lessons with subnetting practice, route lookup, encapsulation explorer, resolver tracer, 14 traced runs, 6 networking tickets; engine: nginx `listen` parsing and bind errors, `ip addr add/del`, ICMP host-unreachable from non-forwarding routers, `traceroute -q`, `nginx -t/-s reload` | ✅ |
| 3c | **DHCP and NAT**: ISC dhcpd model (dhcpd.conf parser, allocation order, lease file, INTERFACESv4), dhclient DORA with real BOOTP bytes, broadcast delivery on the segment; nftables nat chains (masquerade, snat/dnat with ports), per-flow translation reversed for replies, conntrack listing; Internet segment (rtr01 eth2, ext01) and DHCP laptop ws02; two lessons with allocation simulator and NAT inspector, 8 traced runs, 6 tickets with per-ticket terminals | ✅ |
| 3d | Packaging: electron-builder configuration (AppImage/tar.gz, portable exe/zip, dmg/zip), app icon, CI building unsigned executables on Linux, Windows and macOS | ✅ |
| 3e | **VLANs and IPv6**: switch sw01 as a VLAN-aware Linux bridge (ifupdown2 bridge-access/bridge-vids/bridge-pvid, `bridge` command, per-VLAN MAC learning) with cabling (`World.links`); broadcast domains derived from port membership and host tagging (VLAN sub-interfaces); 802.1Q in tcpdump/PCAP; dual-stack engine (addresses incl. link-local, IPv6 routing table, Neighbor Discovery through nftables, ICMPv6 errors, separate IPv6 forwarding), radvd + SLAAC, AAAA records and RFC 6724 ordering, Happy Eyeballs in curl and sequential fallback in ssh; two lessons, 10 traced runs, VLAN and IPv6 explorers, 6 tickets | ✅ |
| 3g | **Operations expansion**: content schema for service guides, case studies, reference library (commands, files/logs, procedures) and certification map; "Operate & recover" tab on every lesson; seven new lessons (systemd/filesystem, network recovery, safe recovery simulated; Windows/RDP, AD/Kerberos, Docker, pfSense as reference lessons); case studies A–G; engine: Debian unit files on disk, `systemctl cat/show/list-dependencies/--failed/is-failed`, `journalctl -f`, `tracepath`, `ethtool`, `cp`/`mv`/`diff`, two case-study tickets; content-integrity tests | ✅ |
| 3f | **MTU and TLS**: interface MTU, packet sizes and DF, router ICMP fragmentation-needed / packet-too-big, PMTU cache (`ip route get`), silent drops on receiving MTU, TCP MSS, segmentation and retransmission backoff, nftables MSS clamping, `ping -s/-M`, `tracepath` PMTU; HTTP server blocks and file serving (status codes, large files), X.509 model (PEM certificates/keys/CSRs, lab CA hierarchy, public roots), OpenSSL-style verification, Debian trust store and `update-ca-certificates`, nginx `listen ssl` with load-time certificate/key checks, curl HTTPS (`-k`, `--cacert`, `--resolve`, `-o`, `-w`), `openssl x509/verify/s_client/req/genrsa/rsa`; stdin/stderr redirection; two lessons with chain inspector and MTU calculator, 8 traced runs, 6 tickets | ✅ |
| 3h | **DHCP relay and renewal, interfaces and virtual switches**: isc-dhcp-relay on rtr01 (giaddr, -id/-iu, packet sockets that bypass nftables), dhcpd subnet selection by giaddr ("unknown network segment"), RFC 2131 lease timers (T1 renew, T2 rebind, expiry, 300 s retry) replayed as simulated time passes (`sleep`), INIT-REBOOT and DHCPNAK, dev02 on VLAN 30; interface engine: bridge device in `ip link`, dummy interfaces, /sys/class/net attributes, ifupdown failure for missing devices; sed addresses and ranges; interfaces lesson with guide, 5 DHCP traced runs, 6 tickets | ✅ |
| 3i | **DHCPv6 and Lab 1**: ISC dhcpd -6 under isc-dhcp-server (INTERFACESv6, dhcpd6.conf, dhcpd6.leases, DUID-LLT), dhclient -6 (Solicit/Advertise/Request/Reply, Information-request, Renew/Rebind/expiry, Release) with nftables applying on both ends, ifupdown `inet6 dhcp`/`autoconf 0`, RA M/O flags, ICMPv6 "beyond scope" for link-local sources; IPv6 lesson sections, 3 visual runs, 3 tickets. Guided labs (`src/engine/labs`): steps with engine-evaluated checks, reference solutions, replay to resume, and a final reboot test; **Lab 1: Basic Linux Server** (srv02 from switch port to hardened web server, 9 steps); `printf`, `grep -e …`, `bridge vlan show dev` | ✅ |
| 4 | **Infrastructure Builder** (`src/engine/builder`, `src/ui/pages/Builder.tsx`): drag-and-drop design of hosts, servers, routers (VLAN sub-interfaces, static routes, forward policy, masquerade) and VLAN-aware switches; validation (addresses, gateways, cabling, VLANs on trunks, firewall vs. services); generation of a `World` from real config files; terminals, reboot-all and a packet tracer listing firewall/NAT decisions; three templates; JSON import/export. VLAN broadcast domains are now per switch | ✅ |
| 5a | **Kerberos and DNS SRV**: SRV/TXT records (zone parser, dig/host -t); MIT KDC and kadmind on ns1 (kdc.conf, kadm5.acl, principal database), KDC location through SRV records, AS exchange with encrypted-timestamp pre-authentication, TGS exchange, lifetimes, 300 s clock skew; kinit, klist, kvno, kdestroy, kadmin(.local) with ktadd/cpw/addprinc; per-host clocks (date, timedatectl, systemd-timesyncd); sshd GSSAPIAuthentication (gssapi-with-mic, keytab kvno, .k5login); lesson "Kerberos and DNS service records", 6 visual runs, 4 tickets; `nft add/delete table/chain`; `$?`/`$VAR` expansion in the shell | ✅ |
| 5b | **Windows Server and PowerShell**: win01 (Windows Server 2022) on the server VLAN; Windows model with services (start types, dependencies, Service Control Manager events), Windows Defender Firewall (profiles, rules, network category) compiled into the packet filter, registry values, event logs (System, Security, Firewall, TerminalServices), local users and groups, IIS, adapters and DNS client; Windows PowerShell 5.1 interpreter (pipeline of objects, formatting views, 5.1 error records, about 100 cmdlets: services, processes, events, accounts, files, registry, NetTCPIP, DnsClient, NetSecurity, Test-NetConnection, Invoke-WebRequest) and console programs (ipconfig, ping, tracert, netstat, nslookup, netsh advfirewall, sc.exe, net, reg, qwinsta, findstr); RDP stages (TCP, TLS, NLA, logon right) with `xfreerdp` on the Linux hosts and logon events; the Windows/RDP lesson becomes simulated with a sandbox; 7 RDP tickets | ✅ |
| 5c | **Active Directory and Lab 2**: dc01 as the domain controller of ad.corp.lab (CORP): AD database (users, groups with nesting, computers, lockout policy), AD-integrated DNS with the DC locator SRV records, forwarders and dynamic registration of members, restartable AD DS; Install-WindowsFeature and Install-ADDSForest; DC location from members (SRV query to their own DNS servers, LDAP ping), domain join with computer accounts, the secure channel (Test-ComputerSecureChannel -Repair, nltest /sc_query, /sc_verify, /dsgetdc), the Domain firewall profile through Network Location Awareness, NTLM pass-through RDP logons with lockout and logon rights through nested domain groups; ActiveDirectory and DnsServer cmdlets, gpresult, gpupdate; mandatory-parameter prompts; the AD lesson becomes simulated; 5 domain tickets; **Lab 2: Windows Domain** (7 verified steps) | ✅ |
| 6a | **Lesson primers and layout**: a beginner layer for every lesson (`Primer` in `content/types.ts`, content in `src/content/primers`, rendered by `PrimerView.tsx`): the short version, an analogy, key ideas each with a lab example checked against the simulator, a step-by-step walkthrough, misconceptions and a self-check, placed before the in-depth text; integrity tests require a complete primer per lesson. Collapsible sidebar (Ctrl+\\, remembered in local storage) | ✅ |
| 6b | **Scored services (competition)**: a scoring-engine goal (`scenarios/scoring.ts`) that logs in once with a password like a Go SSH client and reports Go's error text per layer (DNS, connect, key exchange, authentication with the methods tried, connection closed, check command); account state checked by PAM (`sim/accounts.ts`): account expiry (fatal PAM account check), pam_faillock (common-auth, faillock.conf, tallies in /var/run/faillock cleared at boot); `passwd -S/-l/-u`, `chpasswd`, `chage -l/-E`, `usermod -e`, `faillock`, expiry in /etc/shadow; sshd fix: a Match block in an included file ends with that file; SSH lesson translation table (Go ↔ OpenSSH messages); 5 scored-service tickets | ✅ |
| 6c | **Scored services: reachability**: the engine's own check deadline ("Encountered an unexpected error during the check." / "check timed out. this is most likely due to services timing out") when a SYN gets no answer, "Unable to dial the remote host" + Go's "connect: connection refused" when it gets a reset; `systemctl mask/unmask` (link to /dev/null, start/enable refused, `Loaded: masked`, not started at boot); 5 tickets (`scenarios/scoringReachScenarios.ts`): masked sshd, sshd listening on loopback only, firewall drop, no route back to the engine, refused-then-timed-out (two faults) | ✅ |
| 6d | **Scored services: web and DNS**: the engine's web check (`scoredWebCheck`: one GET like Go's net/http, no redirects, no certificate checks; status code and page content compared; Go's errors for refused, lookup "no such host" / "server misbehaving", malformed response, HTTP to an HTTPS client) and DNS check (`scoredDnsCheck`: one UDP query to the team's server; NXDOMAIN, SERVFAIL, wrong answer, `read udp …: connection refused`); nginx access.log/error.log (403/404 reasons), `namei -l`, `chmod` X, `cp` keeping an existing file's mode, zone files rejecting bad addresses and CNAME with other data; 7 tickets (`scenarios/scoringWebDnsScenarios.ts`): 403 from permissions, defaced page, nginx failed after a certificate rename, HTTP closed for "HTTPS only", hijacked record, SERVFAIL after a typo, DNS allowed over TCP only | ✅ |
| 5 | Windows/AD track (remaining): Group Policy objects, Kerberos for Windows logons, a second DC and replication | ⏳ |
| 6 | **pfSense and Lab 3**: fw01 (pfSense 2.7.2, FreeBSD shell) between the Internet, the server network and a DMZ with dmz01; `/conf/config.xml` as the only state (`src/engine/pf`: XML parser/printer, typed config model), compiled like pfSense's rules.debug into the packet filter with pf semantics (ingress rules, first match, keep state, anti-lockout, block private networks on WAN, logged default deny, rdr before filtering, automatic/hybrid/manual outbound NAT), filterlog lines in /var/log/filter.log, load errors that keep the previous ruleset, restore of the last good config at boot; console tools (`pfctl -s rules/nat/states/info/tables`, `-vvsr`, `-d/-e`, `-k`, `-F states`, `-t … -T show`, `-nf`, `easyrule`, `viconfig`, `/etc/rc.filter_configure`, `/etc/rc.reload_all`, FreeBSD `ifconfig`, `netstat`, `sockstat`); the webConfigurator (`src/ui/components/PfWebConfigurator.tsx` over `pf/webgui.ts`: login, dashboard, interface assignment, aliases, rules with ordering, port forwards with associated rules, outbound NAT modes, firewall log, states, Apply Changes) reached over HTTPS from a browser on ws01, so a bad rule can lock it out; the pfSense lesson becomes simulated with a sandbox; 5 pfSense tickets; **Lab 3: Perimeter firewall** (6 verified steps, reference solutions done in the webConfigurator) | ✅ |
| 7 | Containers: image layers, namespaces, bridge networking, port publishing; Docker Compose; Lab 4 | ⏳ |
| 8 | Enterprise services (web/reverse proxy, SMB/NFS, NTP, logging) and Labs 5–6 (multi-system outages, recovery) | ⏳ |

### Adding a new service (checklist)
1. Engine: add a `ServiceDef` in `sim/services.ts` (start/reload/listeners/config parsing) and any protocol simulator under `sim/` that records `TraceEvent`s.
2. Shell: add the service's admin/diagnostic commands under `shell/`.
3. Content: add a `Lesson` (with a `ServiceGuide`, which is shown across the tabs) and an `Assessment` and register them in `src/content/lessons.ts`; add command, file and procedure entries to the reference library (`src/content/reference/`), glossary entries, and objective links in `src/content/certification.ts`. Mark a command `sim: true` only if it runs in the simulator exactly as written; `tests/content-integrity.test.ts` checks this and every cross-link. Optional interactive widgets are wired in `widgetsFor()` in `src/ui/pages/LessonPage.tsx`.
4. Scenarios: add `Scenario` objects (goals: SSH login, HTTP request or name lookup) with `setup`, `solution` and constraints, and register the set in `src/engine/scenarios/index.ts`; the generic scenario test proves each one breaks and is fixable.
5. Curriculum: flip the topic status to `available` with a link.
